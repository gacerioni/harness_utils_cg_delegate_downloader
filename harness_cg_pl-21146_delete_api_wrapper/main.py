__author__ = "Gabs - Customer Success Engineering"
__copyright__ = "N/A - Feel free to edit and use this at will"
__credits__ = ["Gabriel Cerioni"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Gabriel Cerioni"
__email__ = "gabriel.cerioni@harness.io"
__status__ = "Being tested on Harness on-prem Labs."

import base64
import getopt
import logging
import os
import sys
import re

import requests

# optional - logging.basicConfig(filename='cli.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.DEBUG)

USAGE = f"""
This quick project will run a DELETE on the API provided for ZD Ticket 17671 (Engg Jira PL-21146)!

Usage: python {sys.argv[0]} [-h|--help] | [-v|--version]| <arguments>]

Arguments:
  -h, --help
        displays some help.
  -v, --version
        displays the current version of this CLI.
  -a, --accountId=<YOUR_ACCOUNT_ID>
        here you put your Harness Account ID, the one you can get on any URL after you are logged in.
        example: https://app.harness.io/#/account/SSHyJhwkS1ym9wSLGyw2aw/dashboard
                 My Account ID is: SSHyJhwkS1ym9wSLGyw2aw
  -m, --managerHost=<HARNESS_MASTER_REACHABLE_HOST>
        here you put your on-prem Harness Manager Host.
        example: https://app.harness.io/#/account/SSHyJhwkS1ym9wSLGyw2aw/dashboard
                 My Account ID is: SSHyJhwkS1ym9wSLGyw2aw
  -u, --userMail=<USER_LOGIN_EMAIL>
        here you provide the email, which is the primary login method for Harness CG.
        Alternative: you may export an Environment Variable as `HARNESS_USER` and supress this parameter.
        Example: export HARNESS_USER=gabriel.cerioni@harness.io
  -p, --password=<YOUR_PASSWORD>
        here you provide the password
        Alternative: you may export an Environment Variable as `HARNESS_PWD` and supress this parameter.
        Example: export HARNESS_PWD=super_secret42
        
  
Example on a mixed way to use this CLI:
  export HARNESS_PWD=super_secret42
  python3 main.py -a SSHyJhwkS1ym9wSLGyw2aw --managerHost=harnessmanager.corp.com --userMail gabriel.cerioni@harness.io
  python main.py <WIP>
  
Example on a minimal way to use this CLI, after exporting some sensitive data:
  export HARNESS_USER=gacerioni@harness.io
  export HARNESS_PWD=super_secret42
  python3 main.py <WIP>
"""

HARNESS_USER = os.environ.get('HARNESS_USER')
HARNESS_PWD = os.environ.get('HARNESS_PWD')
HARNESS_ENGG_API_PATH = "/api/usageRestrictions/references/connectors"
HARNESS_LOGIN_API_PATH = "/api/users/login"


def argument_parser():
    # default values for some optional parameters
    username = HARNESS_USER
    username_password = HARNESS_PWD

    options, arguments = getopt.getopt(
        sys.argv[1:],  # Arguments
        "vha:m:u:p:",  # Short option definitions
        ["version", "help", "accountId=", "managerHost=", "userMail=", "password="])  # Long option definitions
    for o, a in options:
        if o in ("-v", "--version"):
            print(__version__)
            sys.exit()
        if o in ("-h", "--help"):
            print(USAGE)
            sys.exit()
        if o in ("-a", "--accountId"):
            account_id = a
        if o in ("-m", "--managerHost"):
            manager_host = a
        if o in ("-u", "--userMail"):
            username = a
        if o in ("-p", "--password"):
            username_password = a

    # Naive way to validate the required parameters.
    # Maybe I should have used another parsing lib
    # I could use list comprehension here, but this might be hard to read in the future
    provided_options = [optinput for optinput, arginput in options]

    if "-a" not in provided_options and "--accountId" not in provided_options:
        print(USAGE)
        logging.error("The following required options was not specified: Account ID")
        sys.exit(1)
    if "-m" not in provided_options and "--managerHost" not in provided_options:
        print(USAGE)
        logging.error("The following required options was not specified: Harness Master Hostname")
        sys.exit(1)
    if ("-u" not in provided_options and "--userMail" not in provided_options) and (HARNESS_USER is None):
        print(USAGE)
        logging.error(
            "The following required options was not specified: User Name. Also, the CLI could not find the HARNESS_USER environment variable.")
        sys.exit(1)
    if ("-p" not in provided_options and "--password" not in provided_options) and (HARNESS_PWD is None):
        print(USAGE)
        logging.error(
            "The following required options was not specified: Password. Also, the CLI could not find the HARNESS_PWD environment variable.")
        sys.exit(1)

    # validating some stuff that would break the API call
    email_rfc_pattern = re.compile(
        """(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""")
    if not email_rfc_pattern.match(username):
        print(USAGE)
        logging.error("Bad User Mail. Please make sure it is a valid e-mail under RFC 5322. This is prone to errors.")
        sys.exit(1)

    argument_dict = {"account_id": account_id, "manager_host": manager_host,
    "username": username, "username_password": username_password}

    return argument_dict


def get_bearer_token(user, password, manager_host):
    user_pwd_pattern = "{0}:{1}".format(user, password)
    encoded_usr_pwd = base64.b64encode(bytes(user_pwd_pattern, 'utf-8')).decode('utf-8')
    full_login_url = "https://{0}{1}".format(manager_host, HARNESS_LOGIN_API_PATH)
    logging.info("This is the LOGIN URL the CLI will use: {0}".format(full_login_url))

    payload = '{{"authorization": "Basic {0}"}}'.format(encoded_usr_pwd)
    logging.debug("This is your payload: {0}".format(payload))

    try:
        logging.info("Generating a fresh Token for user: {0}".format(user))
        response = requests.post(
            full_login_url,
            headers={'Accept': 'application/json, text/plain, */*', 'content-type': 'application/json'},
            data=payload)
        response.raise_for_status()

        # redundant, for educational purposes
        if str(response.status_code).startswith("5"):
            logging.error("Since this is a Server Error (5**), the CLI will exit. Please check the HTTP Response above.")
            sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        logging.error("Http Error:", errh)
        raise
    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting:", errc)
        raise
    except requests.exceptions.Timeout as errt:
        logging.error("Timeout Error:", errt)
        raise
    except requests.exceptions.RequestException as err:
        logging.error("OOps: Something Else", err)
        raise
    else:
        logging.info("Success! Token for user: {0} was created with no issues!".format(user))
        json_response = response.json()
        bearer_token = json_response['resource']['token']
        logging.debug(bearer_token)
        return bearer_token


def delete_api_generic_wrapper(bearer_token, manager_host, api_endpoint, request_payload_dict):
    full_delete_url = "https://{0}{1}".format(manager_host, api_endpoint)

    logging.info("Running DELETE on this URL: {0}".format(full_delete_url))
    try:
        response = requests.get(
            full_delete_url,
            headers={
                'Accept': 'application/json, text/plain, */*',
                'content-type': 'application/json; charset=utf-8',
                'authorization': 'Bearer {0}'.format(bearer_token)
            },
            params=request_payload_dict
        )
        logging.info("HTTP Response/Status Code: {0}".format(response.status_code))
        logging.info("HTTP Response Payload: {0}".format(response.content))

        if str(response.status_code).startswith("5"):
            logging.error("Since this is a Server Error (5**), the CLI will exit. Please check the HTTP Response above.")
            sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        logging.error("Http Error: {0}".format(errh))
        raise
    except requests.exceptions.ConnectionError as errc:
        logging.error("Error Connecting:", errc)
        raise
    except requests.exceptions.Timeout as errt:
        logging.error("Timeout Error:", errt)
        raise
    except requests.exceptions.RequestException as reqerr:
        logging.error("Request Exception: ", reqerr)
        raise
    else:
        json_response = response.json()
        logging.debug(json_response)

        return json_response


def main():
    # 1-) Getting your nice arguments, and doing everything I remember now to make sure they are valid.
    try:
        logging.info("Trying to parse the user-provided input CLI arguments.")
        cli_arguments = argument_parser()
    except requests.exceptions.HTTPError as errh:
        logging.error("Something wrong with your arguments: ", errh)
        raise
    else:
        logging.info("Success! Your arguments seem to be valid!")

    # 2-) Now we'll get a fresh Token to start the work
    session_bearer_token = get_bearer_token(cli_arguments['username'], cli_arguments['username_password'], cli_arguments['manager_host'])
    
    # 3-) Finally, we send the DELETE to the API requested by the Engineer
    delete_usage_restrictions_payload = {"accountId": cli_arguments['account_id']}
    delete_usage_restrictions_result = delete_api_generic_wrapper(session_bearer_token, cli_arguments['manager_host'], HARNESS_ENGG_API_PATH, delete_usage_restrictions_payload)

if __name__ == '__main__':
    main()
