"""Utility functions that help with querying"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
from typing import List, Optional, Union
import re

import botocore.session

from principalmapper.common import Edge, Graph, Node, Policy
from principalmapper.util import arns


logger = logging.getLogger(__name__)


def get_search_list(graph: Graph, node: Node) -> List[List[Edge]]:
    """Returns a list of edge lists. Each edge list represents a path to a new unique node that's accessible from the
    initial node (passed as a param). This is a breadth-first search of nodes from a source node in a graph.
    """
    result = []
    explored_nodes = []

    # Special-case: node is an "admin", so we make up admin edges and return them all
    if node.is_admin:
        result.extend(
            [
                Edge(
                    node,
                    other_node,
                    'can access through administrative actions',
                    'Admin',
                )
            ]
            for other_node in graph.nodes
            if node != other_node
        )

        return result

    # run through initial edges
    result.extend(
        [edge]
        for edge in get_edges_with_node_source(graph, node, explored_nodes)
    )

    explored_nodes.append(node)

    # dig through result list
    index = 0
    while index < len(result):
        current_node = result[index][-1].destination
        result.extend(
            result[index][:] + [edge]
            for edge in get_edges_with_node_source(
                graph, current_node, explored_nodes
            )
        )

        explored_nodes.append(current_node)
        index += 1

    return result


def get_edges_with_node_source(graph: Graph, node: Node, ignored_nodes: List[Node]) -> List[Edge]:
    """Returns a list of nodes that are the destination of edges from the given graph where source of the edge is the
    passed node.
    """
    return [x for x in node.get_outbound_edges(graph) if x.source not in ignored_nodes]


def is_connected(graph: Graph, source: Node, destination: Node) -> bool:
    """helper function to express if source and node are connected"""
    if source.is_admin:
        return True

    return any(
        node_list[-1].destination == destination
        for node_list in get_search_list(graph, source)
    )


def pull_cached_resource_policy_by_arn(graph: Graph, arn: Optional[str], query: str = None) -> Union[Policy, dict]:
    """Function that pulls a resource policy that's cached on-disk from the given Graph object.

    Returns either a Policy object or a dictionary representing the resource policy. Caller is responsible
    for checking before sending it along to other components.

    Raises ValueError if it is not able to be retrieved.
    """
    if query is not None:
        if arn is not None:
            raise ValueError('Must specify either arn or query, not both.')
        pattern = re.compile(r'.*(arn:[^:]*:[^:]*:[^:]*:[^:]*:\S+).*')
        matches = pattern.match(query)
        if matches is None:
            raise ValueError('Resource policy retrieval error: could not extract resource ARN from query')
        arn = matches[1]
    if '?' in arn or '*' in arn:
        raise ValueError('Resource component from query must not have wildcard (? or *) when evaluating '
                         'resource policies.')

    logger.debug(f'Looking for cached policy for {arn}')

    # manipulate the ARN as needed
    service = arns.get_service(arn)
    if service == 's3':
        # we only need the ARN of the bucket
        search_arn = f"arn:{arns.get_partition(arn)}:s3:::{arns.get_resource(arn).split('/')[0]}"

    elif service == 'iam':
        # special case: trust policies
        role_name = arns.get_resource(arn).split('/')[-1]  # get the last part of :role/path/to/role_name
        role_node = graph.get_node_by_searchable_name(f'role/{role_name}')
        return role_node.trust_policy
    elif service == 'sns':
        search_arn = arn
    elif service == 'sqs':
        search_arn = arn
    elif service == 'kms':
        search_arn = arn
    elif service == 'secretsmanager':
        search_arn = arn
    else:
        raise NotImplementedError(
            f'Service policies for {service} are not (currently) cached.'
        )


    for policy in graph.policies:
        if search_arn == policy.arn:
            return policy

    raise ValueError(f'Unable to locate a cached policy for resource {arn}')


def pull_resource_policy_by_arn(session: botocore.session.Session, arn: Optional[str], query: str = None) -> dict:
    """helper function for pulling the resource policy for a resource at the denoted ARN.

    raises ValueError if it cannot be retrieved, or a botocore ClientError if another issue arises
    """
    if query is not None:
        if arn is not None:
            raise ValueError('Must specify either arn or query, not both.')
        pattern = re.compile(r'.*(arn:[^:]*:[^:]*:[^:]*:[^:]*:\S+).*')
        matches = pattern.match(query)
        if matches is None:
            raise ValueError('Resource policy retrieval error: could not extract resource ARN from query')
        arn = matches[1]
        if '?' in arn or '*' in arn:
            raise ValueError('Resource component from query must not have wildcard (? or *) when evaluating '
                             'resource policies.')

    service = arns.get_service(arn)
    if service == 'iam':
        # arn:aws:iam::<account_id>:role/<role_name>
        client = session.create_client('iam')
        role_name = arns.get_resource(arn).split('/')[-1]
        logger.debug(
            f'Calling IAM API to retrieve AssumeRolePolicyDocument of {role_name}'
        )

        return client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
    elif service == 's3':
        # arn:aws:s3:::<bucket>/<path_to_object_with_potential_colons>
        client = session.create_client('s3')
        bucket_name = arns.get_resource(arn).split('arn:aws:s3:::')[-1].split('/')[0]
        logger.debug(f'Calling S3 API to retrieve bucket policy of {bucket_name}')
        return json.loads(client.get_bucket_policy(Bucket=bucket_name)['Policy'])
    elif service == 'sns':
        region = arns.get_region(arn)
        client = session.create_client('sns', region_name=region)
        logger.debug(f'Calling SNS API to retrieve topic policy of {arn}')
        policy_str = client.get_topic_attributes(TopicArn=arn)['Attributes']['Policy']
        return json.loads(policy_str)
    elif service == 'sqs':
        region = arns.get_region(arn)
        client = session.create_client('sqs', region_name=region)
        logger.debug(f'Calling SQS API to retrieve queue policy of {arn}')
        queue_url = f'https://sqs.{arns.get_region(arn)}.amazonaws.com/{arns.get_account_id(arn)}/{arns.get_resource(arn)}'

        policy_str = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])['Policy']
        return json.loads(policy_str)
    elif service == 'kms':
        region = arns.get_region(arn)
        client = session.create_client('kms', region_name=region)
        logger.debug(f'Calling KMS API to retrieve key policy of {arn}')
        return json.loads(
            client.get_key_policy(KeyId=arn, PolicyName='default')['Policy']
        )


def get_interaccount_search_list(all_graphs: List[Graph], inter_account_edges: List[Edge], node: Node) -> List[List[Edge]]:
    """Returns a list of edge lists. Each edge list represents a path to a new unique node that's accessible from the
    initial node (passed as a param). This is a breadth-first search, and the returned list of lists of edges will
    represent the different available paths.
    """

    result = []
    nodes_found = [node]
    account_id_graph_map = {
        graph.metadata['account_id']: graph for graph in all_graphs
    }

    # Get initial list of edges
    first_set = get_edges_interaccount(account_id_graph_map[arns.get_account_id(node.arn)], inter_account_edges, node, nodes_found)
    for found_edge in first_set:
        nodes_found.append(found_edge.destination)
        result.append([found_edge])
    nodes_explored = [node]
    # dig through result list
    index = 0
    while index < len(result):
        current_node = result[index][-1].destination
        if current_node not in nodes_explored:
            for edge in get_edges_interaccount(account_id_graph_map[arns.get_account_id(current_node.arn)], inter_account_edges, current_node, nodes_found):
                result.append(result[index][:] + [edge])
                if edge.destination not in nodes_found:
                    nodes_found.append(edge.destination)
            nodes_explored.append(current_node)
        index += 1

    return result


def get_edges_interaccount(source_graph: Graph, inter_account_edges: List[Edge], node: Node, ignored_nodes: List[Node]) -> List[Edge]:
    """Given a Node, the Graph it belongs to, a list of inter-account Edges, and a list of Nodes to skip, this returns
    any Edges where the Node is the source element as long as the destination element isn't included in the skipped Nodes.

    If the given node is an admin, those Edge objects get generated and returned.
    """

    result = [
        outbound_edge
        for outbound_edge in node.get_outbound_edges(source_graph)
        if outbound_edge.destination not in ignored_nodes
    ]


    for inter_account_edge in inter_account_edges:
        if inter_account_edge.source == node and inter_account_edge.destination not in ignored_nodes:
            result.append(inter_account_edge)

    return result
