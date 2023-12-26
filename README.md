# AWSRoleJuggler
A toolset to juggle AWS roles for persistent access

# Usage
First, use the find_cicular_trust.py tool to locate roles that create a circular trust. This is assuming the calling environment already has credentials loaded for the AWS environment:
```
./find_circular_trust.py 
Found cycle: ['arn:aws:iam::123456789:role/GitRole', 'arn:aws:iam::123456789:role/BuildRole', 'arn:aws:iam::123456789:role/ArtiRole']
```
Next, use the aws_role_juggler.py script to keep a role session alive for an indefinite period of time. In this example, we want to keep the BuildRole alive past the 1 hour max, so we provide the roles in the proper order:
```
python aws_role_juggler.py -r arn:aws:iam::123456789:role/BuildRole arn:aws:iam::123456789:role/GitRole arn:aws:iam::123456789:role/ArtiRole
```
Even though the session is requested for an hour, it is refreshed every 15 minutes, and the credentials are output to screen.

# TODO
* Automatically detect cycles and best direction for aws_role_juggler.
* Write credentials to file for logging
* Adjust session duration based on role max duration

# PSRoleJuggle
Powershell script to check for Role juggling. The script loops thorough the roles and tried to assume each one. If successful, it prints out information.
Note: AWS CLI needs to be installed and AWS credentials need to be configured.

```
powershell.exe .\rolejuggle.ps1
```
