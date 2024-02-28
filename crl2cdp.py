import argparse, keyring, logging, os, smtplib, ssl, sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


############ EDIT BELOW ####################################################################
s3_bucket_name = "mybucketname"
crl_folder_path = r"c:\CDP"

email_server = "smtp.office365.com"
email_port = 587
email_from = "me@domain.com"
email_recipient = "you@domain.com"
email_subject = "crl2cdp notification"
log_file_name = "./logs/crl2cdp.log"
# Setup passwords/secrets by running 'python crl2cdp.py --setup'
############ EDIT ABOVE ####################################################################


def output(message, level=logging.info):
    print(f"\n{message}")
    if not level:
        logging.info(message)
    else:
        level(message)


def set_secrets():
    # Prompt user and set all the secrets
    print("\nJust hit enter if keeping existing secret.\n")
    aws_access_key_id = input("AWS Access Key ID: ")
    aws_secret_access_key = input("AWS Secret Key: ")
    email_password = input("Email Password: ")

    if aws_access_key_id:
        keyring.set_password("crl2cdp", "aws_access_key_id", aws_access_key_id)
    if aws_secret_access_key:
        keyring.set_password("crl2cdp", "aws_secret_access_key", aws_secret_access_key)
    if email_password:
        keyring.set_password("crl2cdp", "email_password", email_password)

    output("All secrets have been updated. Use --get if you need to confirm them.\n")


def get_secrets():
    # Grab all the existing secrets, returns None if they don't exist
    secrets = {}
    secrets["aws_access_key_id"] = keyring.get_password("crl2cdp", "aws_access_key_id")
    secrets["aws_secret_access_key"] = keyring.get_password(
        "crl2cdp", "aws_secret_access_key"
    )
    secrets["email_password"] = keyring.get_password("crl2cdp", "email_password")

    return secrets


def delete_secrets():
    # Prompt user then delete secrets
    answer = ""
    while answer not in ("yes", "no"):
        print(
            "This will delete ALL credentials used by this script from the OS Keychain/Credential Manager."
        )
        answer = input("ARE YOU SURE? (yes/no): ").lower()

    if answer == "yes":
        try:
            keyring.delete_password("crl2cdp", "aws_access_key_id")
            keyring.delete_password("crl2cdp", "aws_secret_access_key")
            keyring.delete_password("crl2cdp", "email_password")
            print(
                "\nAll secrets used by crl2cdp have been removed from the OS Keychain/Credential Manager.\n"
            )

        except keyring.errors.PasswordDeleteError as e:
            print(
                f"\n{e}\n\nError deleting secrets, they may have already been deleted. Check with '-g'.\n"
            )
    else:
        print("\nNo secrets were deleted.\n")


def send_mail(message):
    """
    Send Mail Notification
    """
    # Create SSL Context
    context = ssl.create_default_context()

    # Prepare variables
    email_password = keyring.get_password("crl2cdp", "email_password")
    message = f"Subject: {email_subject}\n\n\n{message}\n\n\n"

    # Create Connection, uncomment server.login() if using authentication.
    try:
        with smtplib.SMTP(email_server, email_port) as server:
            server.starttls(context=context)
            server.login(email_from, email_password)
            server.sendmail(email_from, email_recipient, message)
            output(f"Email sent to {email_recipient}.")
    except smtplib.SMTPAuthenticationError as e:
        message = "\n\nFAILED sending email, please check email settings.\n"
        message += f"\nError was: \n{e}\n{type(e)}"
    except Exception as e:
        message = "\n\nFAILED sending email, please check email settings.\n"
        message += f"\nError was: \n{e}\n{type(e)}"
        logging.error(message)
        print(message)


# def s3_get_bucket_names(s3):
#     buckets = s3.buckets.all()
#     names = []
#     for bucket in buckets:
#         names.append(bucket.name)

#     return names


def s3_upload(
    aws_access_key_id: str, aws_secret_access_key: str, email_password: str
) -> None:
    """
    Upload CRL Files to S3
    """
    crl_and_crt_files = [
        file for file in os.listdir(crl_folder_path) if file.endswith((".crl", ".crt"))
    ]

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        s3 = session.client("s3")
        for filename in crl_and_crt_files:
            # with open(filename, "rb") as data:
            #     s3.Bucket(s3_bucket_name).put_object(Key=filename, Body=data)
            s3.upload_file(filename, s3_bucket_name, filename)
            output(f"Uploaded {filename} to S3.")
        # bucket_names = s3_get_bucket_names(s3)
    except ClientError as e:
        output(f"AWS Login Error: {e}", logging.error)
        sys.exit(1)
    except NoCredentialsError as e:
        output(f"Unable to get AWS Credentials, check -g (get secrets)", logging.error)
        sys.exit(1)


if __name__ == "__main__":

    # Logging
    os.makedirs("./logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        filename=log_file_name,
        format="%(asctime)s - %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
    )

    # Check for arguments
    parser = argparse.ArgumentParser(
        description="Use --setup to initaliize the secrets."
    )
    parser.add_argument(
        "-s",
        "--setup",
        help="Set the secrets and passwords to be used.",
        action="store_true",
    )
    parser.add_argument(
        "-g",
        "--getsecrets",
        help="Get the secrets and passwords that will be used.",
        action="store_true",
    )
    parser.add_argument(
        "-u", "--upload", help="Upload the CRL files to S3", action="store_true"
    )
    parser.add_argument(
        "-xx",
        "--delete",
        help="Delete all secrets from the OS Keychain/Credential Store.",
        action="store_true",
    )
    args = parser.parse_args()

    # Gather Secrets
    secrets = get_secrets()

    # Run based on arguments given
    if args.setup:
        # Configure Secrets
        set_secrets()
    elif args.getsecrets:
        secrets = get_secrets()
        print()
        for secret, value in secrets.items():
            print(f"{secret} = {value}")
        print()
    elif args.upload:
        # Check that secrets exist before running
        if any(secret is None for secret in secrets.values()):
            print(
                "\nError, unable to find all secrets, please run with --setup to configure these variables.\n"
            )
            sys.exit(0)
        # s3_upload(**secrets)
        send_mail("WHY HELLO THERE!!!")
    elif args.delete:
        delete_secrets()
    else:
        # Check that secrets exist before running
        if None in {**secrets}:
            print(
                "\nError, unable to find secrets, please run with --setup to configure these variables.\n"
            )
            sys.exit(0)
        else:  # Default to Upload
            s3_upload(**secrets)
