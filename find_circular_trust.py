#!/usr/bin/env python3

import boto3
import json
import networkx as nx


def iam_list_roles():
    iam_client = boto3.client("iam")
    roles = []
    response = {}
    is_truncated = False

    try:
        while len(response.keys()) == 0 or is_truncated is True:
            if is_truncated is False:
                response = iam_client.list_roles()
            else:
                response = iam_client.list_roles(Marker=response["Marker"])

            for role in response["Roles"]:
                roles.append(role)

            is_truncated = response["IsTruncated"]
        return roles
    except Exception as e:
        raise


def getCycles(aws_roles):
    g = nx.DiGraph()
    for role in aws_roles:
        g.add_nodes_from([role["Arn"]])

    for role in aws_roles:
        for statement in role["AssumeRolePolicyDocument"]["Statement"]:
            if statement["Effect"] == "Allow" and "AWS" in statement["Principal"]:
                arns = statement["Principal"]["AWS"]
                source = role["Arn"]
                if isinstance(arns, list):
                    for arn in arns:
                        dest = arn
                        g.add_edges_from([(source, dest)])
                else:
                    dest = arns
                    g.add_edges_from([(source, dest)])

    cycles = list(nx.simple_cycles(g))
    return cycles


if __name__ == "__main__":
    client = boto3.client("iam")
    aws_roles = iam_list_roles()

    cycles = getCycles(aws_roles)
    for c in cycles:
        print(f"Found cycle: {c}")
