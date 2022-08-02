"""Code to identify if a principal in an AWS account can use access to CloudFormation to access other principals."""

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

import io
import logging
import os
from typing import List, Optional

from botocore.exceptions import ClientError

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns, botocore_tools


logger = logging.getLogger(__name__)


class CloudFormationEdgeChecker(EdgeChecker):
    """Class for identifying if CloudFormation can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Pulling data on CloudFormation stacks.')

        if client_args_map is None:
            cfargs = {}
        else:
            cfargs = client_args_map.get('cloudformation', {})

        # Grab existing stacks in each region
        cloudformation_clients = []
        if self.session is not None:
            cf_regions = botocore_tools.get_regions_to_search(self.session, 'cloudformation', region_allow_list, region_deny_list)
            cloudformation_clients.extend(
                self.session.create_client(
                    'cloudformation', region_name=region, **cfargs
                )
                for region in cf_regions
            )

        # grab existing cloudformation stacks
        stack_list = []
        for cf_client in cloudformation_clients:
            logger.debug(f'Looking at region {cf_client.meta.region_name}')
            try:
                paginator = cf_client.get_paginator('describe_stacks')
                for page in paginator.paginate():
                    stack_list.extend(
                        stack
                        for stack in page['Stacks']
                        if stack['StackStatus']
                        not in [
                            'CREATE_FAILED',
                            'DELETE_COMPLETE',
                            'DELETE_FAILED',
                            'DELETE_IN_PROGRESS',
                        ]
                    )

            except ClientError as ex:
                logger.warning(
                    f'Unable to search region {cf_client.meta.region_name} for stacks. The region may be disabled, or the error may be caused by an authorization issue. Continuing.'
                )

                logger.debug(f'Exception details: {ex}')

        logger.info('Generating Edges based on data from CloudFormation.')
        result = generate_edges_locally(nodes, stack_list, scps)

        for edge in result:
            logger.info(f"Found new edge: {edge.describe_edge()}")
        return result


def generate_edges_locally(nodes: List[Node], stack_list: List[dict], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. Works on the assumption that the param `stack_list` is the
    collected outputs from calling `cloudformation:DescribeStacks`. Thus, it is possible to
    create a similar output and feed it to this method if you are operating offline (infra-as-code).
    """

    result = []

    for node_destination in nodes:
        # check if the destination is a role
        if ':role/' not in node_destination.arn:
            continue

        # check that the destination role can be assumed by CloudFormation
        sim_result = resource_policy_authorization(
            'cloudformation.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {}
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # CloudFormation wasn't auth'd to assume the role

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # Get iam:PassRole info
            can_pass_role, need_mfa_passrole = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                {
                    'iam:PassedToService': 'cloudformation.amazonaws.com'
                },
                service_control_policy_groups=scps
            )

            # See if source can make a new stack and pass the destination role
            if can_pass_role:
                can_create, need_mfa_create = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'cloudformation:CreateStack',
                    '*',
                    {'cloudformation:RoleArn': node_destination.arn},
                    service_control_policy_groups=scps
                )
                if can_create:
                    reason = 'can create a stack in CloudFormation to access'
                    if need_mfa_passrole or need_mfa_create:
                        reason = f'(MFA required) {reason}'

                    result.append(Edge(node_source, node_destination, reason, 'Cloudformation'))

            relevant_stacks = [
                stack
                for stack in stack_list
                if 'RoleARN' in stack
                and stack['RoleARN'] == node_destination.arn
            ]

            # See if source can call UpdateStack to use the current role of a stack (setting a new template)
            for stack in relevant_stacks:
                can_update, need_mfa_update = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'cloudformation:UpdateStack',
                    stack['StackId'],
                    {'cloudformation:RoleArn': node_destination.arn},
                    service_control_policy_groups=scps
                )
                if can_update:
                    reason = f"can update the CloudFormation stack {stack['StackId']} to access"
                    if need_mfa_update:
                        reason = f'(MFA required) {reason}'

                    result.append(Edge(node_source, node_destination, reason, 'Cloudformation'))
                    break  # let's save ourselves having to dig into every CF stack edge possible

            # See if source can call UpdateStack to pass a new role to a stack and use it
            if can_pass_role:
                for stack in stack_list:
                    can_update, need_mfa_update = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'cloudformation:UpdateStack',
                        stack['StackId'],
                        {'cloudformation:RoleArn': node_destination.arn},
                        service_control_policy_groups=scps
                    )

                    if can_update:
                        reason = f"can update the CloudFormation stack {stack['StackId']} and pass the role to access"

                        if need_mfa_update or need_mfa_passrole:
                            reason = f'(MFA required) {reason}'

                        result.append(Edge(node_source, node_destination, reason, 'Cloudformation'))
                        break  # save ourselves from digging into all CF stack edges possible

            # See if source can call CreateChangeSet and ExecuteChangeSet to alter a stack with a given role
            for stack in relevant_stacks:
                can_make_cs, need_mfa_make = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'cloudformation:CreateChangeSet',
                    stack['StackId'],
                    {'cloudformation:RoleArn': node_destination.arn},
                    service_control_policy_groups=scps
                )
                if not can_make_cs:
                    continue

                can_exe_cs, need_mfa_exe = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'cloudformation:ExecuteChangeSet',
                    stack['StackId'],
                    {},  # docs say no RoleArn context here
                    service_control_policy_groups=scps
                )

                if can_exe_cs:
                    reason = f"can create and execute a changeset in CloudFormation for stack {stack['StackId']} to access"

                    if need_mfa_make or need_mfa_exe:
                        reason = f'(MFA required) {reason}'

                    result.append(Edge(node_source, node_destination, reason, 'Cloudformation'))
                    break  # save ourselves from digging into all CF stack edges possible

    return result
