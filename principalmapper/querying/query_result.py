"""Class representation of a query result."""


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
import json
import os
from typing import List, Union

from principalmapper.common import Edge, Node


class QueryResult(object):
    """Query result object returned by querying methods. The allowed field specifies if the passed Node is authorized
    to make the API call. The edge_list field, if not an empty list, specifies which edges the Node must traverse
    to make the API call.

    **Change, v1.1.x:** If the edge_list param contains the same node as the node param, it's the special case where
    node is an admin, but could not directly call the API with its perms and had to "use" its admin perms to gain the
    necessary access to call the API.
    """
    def __init__(self, allowed: bool, edge_list: Union[List[Edge], Node], node: Node):
        self.allowed = allowed
        self.edge_list = edge_list
        self.node = node

    def print_result(self, action_param: str, resource_param: str):
        """Prints information about the QueryResult object to stdout."""
        if self.allowed:
            if isinstance(self.edge_list, Node):
                if self.edge_list == self.node:
                    # node is an Admin but can't directly call the action
                    print(
                        f'{self.node.searchable_name()} CAN BECOME authorized to call action {action_param} for resource {resource_param} THRU its admin privileges'
                    )

                else:
                    raise ValueError('Improperly-generated QueryResult object: edge_list is a Node but not the input Node')

            elif len(self.edge_list) == 0:
                # node itself is auth'd
                print(
                    f'{self.node.searchable_name()} IS authorized to call action {action_param} for resource {resource_param}'
                )

            else:
                # node is auth'd through other nodes
                print(
                    f'{self.node.searchable_name()} CAN call action {action_param} for resource {resource_param} THRU {self.edge_list[-1].destination.searchable_name()}'
                )


                # print the path the node has to take
                for edge in self.edge_list:
                    print(f'   {edge.describe_edge()}')

                # print that the end-edge is authorized to make the call
                print(
                    f'   {self.edge_list[-1].destination.searchable_name()} IS authorized to call action {action_param} for resource {resource_param}'
                )

        else:
            print(
                f'{self.node.searchable_name()} CANNOT call action {action_param} for resource {resource_param}'
            )

    def write_result(self, action_param: str, resource_param: str, output: io.StringIO):
        """Writes information about the QueryResult object to the given IO interface.

        **Change, v1.1.x:** The `output` param is no longer optional.
        """

        if self.allowed:
            if isinstance(self.edge_list, Node) and self.edge_list == self.node:
                # node is an Admin but can't directly call the action
                output.write(
                    f'{self.node.searchable_name()} IS authorized to call action {action_param} for resource {resource_param} THRU its admin privileges\n'
                )

            if len(self.edge_list) == 0:
                # node itself is auth'd
                output.write(
                    f'{self.node.searchable_name()} IS authorized to call action {action_param} for resource {resource_param}\n'
                )


            else:
                # node is auth'd through other nodes
                output.write(
                    f'{self.node.searchable_name()} CAN call action {action_param} for resource {resource_param} THRU {self.edge_list[-1].destination.searchable_name()}\n'
                )


                # print the path the node has to take
                for edge in self.edge_list:
                    output.write(f'   {edge.describe_edge()}\n')

                # print that the end-edge is authorized to make the call
                output.write(
                    f'   {self.edge_list[-1].destination.searchable_name()} IS authorized to call action {action_param} for resource {resource_param}\n'
                )

        else:
            output.write(
                f'{self.node.searchable_name()} CANNOT call action {action_param} for resource {resource_param}\n'
            )

    def as_json(self):
        """Produces a JSON representation of this query's result."""
        if isinstance(self.edge_list, Node):
            edge_rep = [{
                'src': self.edge_list.arn,
                'dst': self.edge_list.arn
            }]
        else:
            edge_rep = [
                {'src': edge.source.arn, 'dst': edge.destination.arn}
                for edge in self.edge_list
            ]

        return json.dumps({
            'allowed': self.allowed,
            'node': self.node.arn,
            'edge_list': edge_rep
        })
