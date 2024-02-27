# crl2cdp

## Install
- Create Local Windows User Account that will run this script as a scheduled task, login as that user.

- Install Python 3.11+ (www.python.org)
- Create Folder where CRL files will be contained
- Clone Repo to any local destination (https://github.com/nopg/crl2cdp.git)
    ```
    git clone https://github.com/nopg/crl2cdp.git
    ```
    ( If running windows, download .zip from above and extract files instead )

- Create Virtual Environment
    ```
    python -m venv venv
    ```
- Enter the Virtual Environment
    ```
    source venv/bin/activate (mac/linux)
    .\venv\Scripts\activate.bat (windows)
    ```
- Install crl2cdp requirements
    ```
    pip install -r requirements.txt
    ```

## Initial Setup
- Open crl2cdp.py and update required settings
    ```python
    s3_bucket_name = "mybucketname"
    crl_folder_path = r"c:\CDP"

    email_server = "smtp.office365.com"
    email_port = 587
    email_from = "me@domain.com"
    email_recipient = "you@domain.com"
    email_subject = "crl2cdp notification"
    log_file_name = "./logs/crl2cdp.log"
    ```
- Set your AWS Secrets
    ```
    python crl2cdp.py --setup
    ```
    It will prompt for the following secrets, which you must setup in AWS IAM & Email:
    - aws_access_key_id
    - aws_secret_access_key
    - email_password


## Usage
All commands below must be entered after entering the Virtual Environment (see Install steps) and secrets/credentials have been added via --setup. Also don't forget to update the crl2cdp.py file with your exact S3 bucket name and mail server options.

- Upload Files
    ```
    python crl2cdp.py --upload
    ```

- Get Help
    ```
    python crl2cdp.py --help
    or
    python crl2dp.py -h
    ---------------------------------------------------------------------------
    usage: crl2cdp.py [-h] [-s] [-g] [-u] [-xx]

    Use --setup to initaliize the secrets.

    options:
    -h, --help        show this help message and exit
    -s, --setup       Set the secrets and passwords to be used.
    -g, --getsecrets  Get (and display) the secrets and passwords that will be used.
    -u, --upload      Upload the CRL files to S3
    -xx, --delete     Delete all secrets from the OS Keychain/Credential Store.
    ```
