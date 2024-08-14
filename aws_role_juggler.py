#!/usr/bin/env python3

from argparse import ArgumentParser
import boto3
import json
import os
import time

ACCESS_ID = "AWS_ACCESS_KEY_ID"
SECRET_KEY = "AWS_SECRET_ACCESS_KEY"
SESSION_KEY = "AWS_SESSION_TOKEN"


def assumeRole(client, arn):
    response = client.assume_role(RoleArn=arn, RoleSessionName="juggle", DurationSeconds=3600)

    if not response:
        print("[!] Failed to assume role. Exiting.")
        return

    if "Credentials" not in response:
        print("[!] No credentials returned. Exiting.")
        return

    credentials = response["Credentials"]

    session = boto3.session.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )

    client = session.client("sts")

    print(f"[*] Expiration: {credentials['Expiration']}")

    print(f"{'export AWS_ACCESS_KEY_ID=' if args.export else ''}{credentials['AccessKeyId']}")
    print(f"{'export AWS_SECRET_ACCESS_KEY=' if args.export else ''}{credentials['SecretAccessKey']}")
    print(f"{'export AWS_SESSION_TOKEN=' if args.export else ''}{credentials['SessionToken']}")
    print()  # newline
    return client


def juggleRoles(roleList):
    client = boto3.client("sts")

    first_role = roleList.pop(0)
    roleList.append(first_role)
    # order correctly from command line.
    # python aws_role_juggler.py -r a b
    # becomes [b, a], however when we start chaining the calls, we want it to be [a,b]
    roleList.reverse()

    try:
        while True:
            for i, role in enumerate(roleList, start=1):
                print(f"[i] {i}/{len(roleList)} Attempting to assume role ARN: {role}")
                client = assumeRole(client, role)
            print("[*] Sleeping for 15 minutes and then refreshing session.")
            time.sleep(540)

    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-r", "--role-list", help="roles to assume", nargs="+", default=[])
    parser.add_argument(
        "--export",
        help="prepends export statements for easy copy+paste on linux command line",
        action="store_true",
    )
    args = parser.parse_args()

    juggleRoles(args.role_list)
