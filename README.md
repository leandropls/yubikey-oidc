# Yubikey OIDC

Log into AWS using Yubikey and OIDC.

This tool allows the user to connect to AWS using OIDC. To do so, the user must create a domain to work as the OIDC issuer, where AWS will find `https://domain/.well-known/openid-configuration` as well as `https://domain/.well-known/jwks.json`.

This OIDC provider must then be registered to the desired AWS account and a role must be authorized to be assumed through its trust policy. A sample trust policy can be generated by the tool as well.

The tool can be used to generate an RSA key inside the Yubikey, in PIV slots 9a to 9c. With the help of this tool, the key can be used to generate tokens which can be swapped for AWS credentials through `AssumeRoleWithWebIdentity`.

After everything is set up, running the tool with the `login` command uses the Yubikey to sign a token, swap it for a set of AWS credentials, and configure these credentials to a profile on the user's machine.

The reason for all of this is to allow the user to have a way to easily connect their computer to AWS without storing long-term credentials on their machines, and requiring physical access to the token to log in.


## Table of Contents

- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installing from PyPI](#installing-from-pypi)
  - [Installing from Source](#installing-from-source)
- [Usage](#usage)
  - [Commands](#commands)
    - [generate-public-key](#generate-public-key)
    - [create-token](#create-token)
    - [deploy-openid](#deploy-openid)
    - [create-trust-policy](#create-trust-policy)
    - [assume-role](#assume-role)
    - [login](#login)
- [License](#license)

## Installation

### Prerequisites

Before you can use this package, you must have the following tools installed:

- `ykman`: [Yubikey Manager CLI](https://docs.yubico.com/software/yubikey/tools/ykman/)
- `yubico-piv-tool`: [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/)

### Installing from Source

To install from the source, follow these steps:

```bash
# Clone the repository
git clone https://github.com/leandropls/yubikey-oidc.git

# Navigate to the project directory
cd yubikey-oidc

# Install the package
pip install .
```

## Usage

To use the CLI, you can run the following commands after installing the package.

```bash
yubid <command> [OPTIONS]
```

### Commands

#### `generate-public-key`

Generate a public key from a Yubikey slot.

```bash
yubid generate-public-key --iss <ISS> --sub <SUB> --slot <SLOT>
```

#### `create-token`

Create a token.

```bash
yubid create-token --iss <ISS> --sub <SUB> --slot <SLOT> --duration <DURATION>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier
- `--duration`: Token expiration duration in seconds

#### `print-jwks`

Print the JWKS configuration for the issuer.

```bash
yubid print-jwks --iss <ISS> --sub <SUB> --slot <SLOT>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier

#### `print-openid-configuration`

Print the OpenID configuration for the issuer.

```bash
yubid print-openid-configuration --iss <ISS> --sub <SUB> --slot <SLOT>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier

#### `deploy-openid`

Deploy OpenID configuration to an S3 bucket.

```bash
yubid deploy-openid --iss <ISS> --sub <SUB> --slot <SLOT> --s3-bucket <S3_BUCKET>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier
- `--s3-bucket`: S3 bucket name for deployment

#### `create-trust-policy`

Create a trust policy for a given AWS account.

```bash
yubid create-trust-policy --iss <ISS> --sub <SUB> --slot <SLOT> --account <ACCOUNT>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier
- `--account`: AWS account ID

#### `assume-role`

Assume an AWS role.

```bash
yubid assume-role --iss <ISS> --sub <SUB> --slot <SLOT> --rolearn <ROLEARN> --duration <DURATION>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier
- `--rolearn`: AWS role ARN
- `--duration`: Role assumption duration in seconds

#### `login`

Login to AWS using a specified profile.

```bash
yubid login --iss <ISS> --sub <SUB> --slot <SLOT> --profile <PROFILE> --rolearn <ROLEARN> --duration <DURATION>
```

- `--iss`: Issuer URL
- `--sub`: Subject identifier
- `--slot`: Yubikey slot identifier
- `--profile`: AWS profile name
- `--rolearn`: AWS role ARN
- `--duration`: Session duration in seconds

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
