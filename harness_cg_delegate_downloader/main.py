__author__ = "Gabs - Customer Success Engineering"
__copyright__ = "N/A - Feel free to edit and use this at will"
__credits__ = ["Gabriel Cerioni"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Gabriel Cerioni"
__email__ = "gabriel.cerioni@harness.io"
__status__ = "Focusing on safe guard rails, but not performance."

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
This CLI will Download a Delegate Bundle tar.gz for you. This is still being developed!

Usage: python {sys.argv[0]} [-h|--help] | [-v|--version]| <arguments>]

Arguments:
  -h, --help
        display some help for the champion
  -v, --version
        display the current version of this CLI
  -a, --accountId=<YOUR_ACCOUNT_ID>
        here you put your Harness Account ID, the one you can get on any URL after you are logged in.
        example: https://app.harness.io/#/account/SSHyJhwkS1ym9wSLGyw2aw/dashboard
                 My Account ID is: SSHyJhwkS1ym9wSLGyw2aw
  -k, --delegateType=<SUPPORTED_DELEGATE_TYPE>
        here you put your Harness Account ID, the one you can get on any URL after you are logged in.
        example: https://app.harness.io/#/account/SSHyJhwkS1ym9wSLGyw2aw/dashboard
                 My Account ID is: SSHyJhwkS1ym9wSLGyw2aw
  -d, --delegateName=<DELEGATE_NAME>
        here you put your desired Delegate Name
        Attention: The CLI will fail if the Delegate name still exists. I will verify this on the next version.
        Attention 2: Since this can be used to download K8s Delegates, that are StatefulSets, your Delegate name must match this regex: `^[a-z0-9-]+$`
  -p, --profileId=<DELEGATE_PROFILE_ID>
        here there are no current methods to get this via GraphQL
        my suggestion is for you to simulate a Delegate Download on the UI;
        and then you collect the ID from the URL GET Parameters.
        Example: https://app.harness.io<...>&delegateProfileId=wwCztcb8RXe_BV-G9r3mrA<...>
  -t, --tokenName=<DELEGATE_TOKEN_NAME>
        here you put your Delegate Token Name
        Optional: if you supress this parameter, the CLI will send a `default` string to the API.
  -u, --userMail=<USER_LOGIN_EMAIL>
        here you provide the email, which is the primary login method for Harness CG.
        Alternative: you may export an Environment Variable as `HARNESS_USER` and supress this parameter.
        Example: export HARNESS_USER=gabriel.cerioni@harness.io
  -s, --password=<YOUR_PASSWORD>
        here you provide the password
        Alternative: you may export an Environment Variable as `HARNESS_PWD` and supress this parameter.
        Example: export HARNESS_PWD=super_secret42
        
  
Example on a mixed way to use this CLI:
  python main.py --accountId=SSHyJhwkS1ym9wSLGyw2aw -k shell -d gabs-del --profileId=PtIuIQLiQjaQBub5Yeyzbw -t custom -u gabriel.cerioni@harness.io --password super_secret42
  python main.py --accountId=SSHyJhwkS1ym9wSLGyw2aw --delegateType=shell -d gabs-del --profileId=PtIuIQLiQjaQBub5Yeyzbw -u gabriel.cerioni@harness.io --password super_secret42
  
Example on a minimal way to use this CLI, after exporting some sensitive data:
  export HARNESS_USER=gacerioni@harness.io
  export HARNESS_PWD=super_secret42
  python3 main.py --accountId=SSHyJhwkS1ym9wSLGyw2aw -dgabs-del --profileId=1234
"""

HARNESS_USER = os.environ.get('HARNESS_USER')
HARNESS_PWD = os.environ.get('HARNESS_PWD')
SUPPORTED_DELEGATE_TYPE_ARGUMENT_OPTS = ["shell", "docker", "ecs", "kubernetes"]


def argument_parser():
    # default values for some optional parameters
    token_name = "default"
    delegate_kind = "shell"
    username = HARNESS_USER
    username_password = HARNESS_PWD

    options, arguments = getopt.getopt(
        sys.argv[1:],  # Arguments
        "vha:k:d:p:t:u:s:",  # Short option definitions
        ["version", "help", "accountId=", "delegateType=", "delegateName=", "profileId=", "tokenName=", "userMail=",
         "password="])  # Long option definitions
    for o, a in options:
        if o in ("-v", "--version"):
            print(__version__)
            sys.exit()
        if o in ("-h", "--help"):
            print(USAGE)
            sys.exit()
        if o in ("-a", "--accountId"):
            account_id = a
        if o in ("-k", "--delegateType"):
            if a in SUPPORTED_DELEGATE_TYPE_ARGUMENT_OPTS:
                delegate_kind = a
            else:
                print(USAGE)
                logging.error("The provided Delegate kind/type is incorrect or is not supported yet. Please check the CLI `-k` option.")
                sys.exit(1)
        if o in ("-d", "--delegateName"):
            delegate_name = a
        if o in ("-p", "--profileId"):
            profile_id = a
        if o in ("-t", "--tokenName"):
            token_name = a
        if o in ("-u", "--userMail"):
            username = a
        if o in ("-s", "--password"):
            username_password = a

    # Naive way to validate the required parameters, because I'm a little old-school.
    # Maybe I should have used another parsing lib
    # I could use list comprehension here, but this might be hard to read in the future
    provided_options = [optinput for optinput, arginput in options]

    if "-a" not in provided_options and "--accountId" not in provided_options:
        print(USAGE)
        logging.error("The following required options was not specified: Account ID")
        sys.exit(1)
    if "-d" not in provided_options and "--delegateName" not in provided_options:
        print(USAGE)
        logging.error("The following required options was not specified: Delegate Name")
        sys.exit(1)
    if "-p" not in provided_options and "--profileId" not in provided_options:
        print(USAGE)
        logging.error("The following required options was not specified: Profile ID")
        sys.exit(1)
    if ("-u" not in provided_options and "--userMail" not in provided_options) and (HARNESS_USER is None):
        print(USAGE)
        logging.error(
            "The following required options was not specified: User Name. Also, the CLI could not find the HARNESS_USER environment variable.")
        sys.exit(1)
    if ("-s" not in provided_options and "--password" not in provided_options) and (HARNESS_PWD is None):
        print(USAGE)
        logging.error(
            "The following required options was not specified: Password. Also, the CLI could not find the HARNESS_PWD environment variable.")
        sys.exit(1)

    # validating some stuff that would break the API call
    delegate_name_pattern = re.compile("^[a-z0-9-]+$")
    if not delegate_name_pattern.match(delegate_name):
        print(USAGE)
        logging.error("Bad Delegate name. Please make sure it uses this regex pattern: `^[a-z0-9-]+$`")
        sys.exit(1)

    email_rfc_pattern = re.compile(
        """(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""")
    if not email_rfc_pattern.match(username):
        print(USAGE)
        logging.error("Bad User Mail. Please make sure it is a valid e-mail under RFC 5322. This is prone to errors.")
        sys.exit(1)

    argument_dict = {"account_id": account_id, "delegate_name": delegate_name, "profile_id": profile_id,
                     "token_name": token_name, "username": username, "username_password": username_password}

    return argument_dict


def get_bearer_token(user, password):
    user_pwd_pattern = "{0}:{1}".format(user, password)
    encoded_usr_pwd = base64.b64encode(bytes(user_pwd_pattern, 'utf-8')).decode('utf-8')

    payload = '{{"authorization": "Basic {0}"}}'.format(encoded_usr_pwd)
    logging.debug("This is your payload: {0}".format(payload))

    try:
        logging.info("Generating a fresh Token for user: {0}".format(user))
        response = requests.post(
            'https://app.harness.io/gateway/api/users/login',
            headers={'Accept': 'application/json, text/plain, */*', 'content-type': 'application/json'},
            data=payload)
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


def get_delegate_signed_url(bearer_token, account_id):
    logging.info("Generating a Delegate Signed URL for Account: {0}".format(account_id))
    payload = {'accountId': account_id}
    try:
        response = requests.get(
            'https://app.harness.io/gateway/api/setup/delegates/downloadUrl',
            headers={
                'Accept': 'application/json, text/plain, */*',
                'content-type': 'application/json; charset=utf-8',
                'authorization': 'Bearer {0}'.format(bearer_token)
            },
            params=payload
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
        logging.debug(json_response['resource'])
        logging.info("Success! Delegate Download signed URL was generated for Account: {0}!".format(account_id))
        shell_delegate_signed_url = json_response['resource']['downloadUrl']
        docker_delegate_signed_url = json_response['resource']['dockerUrl']
        ecs_delegate_signed_url = json_response['resource']['ecsUrl']
        kubernetes_delegate_signed_url = json_response['resource']['kubernetesUrl']
        return shell_delegate_signed_url, docker_delegate_signed_url, ecs_delegate_signed_url, kubernetes_delegate_signed_url


def get_final_delegate_download_url(del_signed_url, delegate_name, delegate_profile_id, delegate_token_name="default"):
    logging.info(
        "Crafting the final URL by appending: Delegate Name: {0}, Delegate Profile ID: {1}, Delegate Token Name: {2}.".format(
            delegate_name, delegate_profile_id, delegate_token_name))
    final_download_url = "{0}&delegateName={1}&delegateProfileId={2}&tokenName={3}".format(del_signed_url,
                                                                                           delegate_name,
                                                                                           delegate_profile_id,
                                                                                           delegate_token_name)

    logging.info("Final URL is: {0}".format(final_download_url))
    return final_download_url


def download_delegate_bundle_tgz(final_download_url, result_file_name):
    try:
        logging.info("Downloading the Delegate Bundle TGZ tar.gz. {0}")
        logging.debug("This is the final URL: {0}".format(final_download_url))
        response = requests.get(final_download_url)
        logging.info("HTTP Response/Status Code: {0}".format(response.status_code))
        logging.info("HTTP Response Payload: {0}".format(response.content))
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
        file_name = "{0}.tar.gz".format(result_file_name)
        open(file_name, 'wb').write(response.content)


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
    session_bearer_token = get_bearer_token(cli_arguments['username'], cli_arguments['username_password'])

    # 3-) Time to collect all URLs that represent each Delegate Type (currently).
    shell_url, docker_url, ecs_url, kubernetes_url = get_delegate_signed_url(session_bearer_token,
                                                                             cli_arguments['account_id'])

    # 4-) Producing a good final URL
    final_url = get_final_delegate_download_url(del_signed_url=shell_url, delegate_name=cli_arguments['delegate_name'],
                                                delegate_token_name=cli_arguments['token_name'],
                                                delegate_profile_id=cli_arguments['profile_id'])

    # 5-) Downloading the Delegate as tar.gz
    download_delegate_bundle_tgz(final_url, cli_arguments['delegate_name'])


if __name__ == '__main__':
    main()
