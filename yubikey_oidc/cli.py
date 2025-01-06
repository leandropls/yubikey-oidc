from datetime import timedelta

import click

from yubikey_oidc.core import AwsCredentials, YubikeyOIDC


@click.group()
def cli() -> None:
    """A CLI for YubikeyOIDC operations."""
    pass


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
def generate_public_key(iss: str, sub: str, slot: str) -> None:
    """Generate a public key."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    click.echo(oidc.generate_public_key())


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
@click.option(
    "--duration", required=True, type=int, help="Token expiration duration in seconds"
)
def create_token(iss: str, sub: str, slot: str, duration: int) -> None:
    """Create a token."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    exp = timedelta(seconds=duration)
    token = oidc.create_token(exp)
    click.echo(token)


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
@click.option(
    "--s3-bucket", required=True, type=str, help="S3 bucket name for deployment"
)
def deploy_openid(iss: str, sub: str, slot: str, s3_bucket: str) -> None:
    """Deploy OpenID configuration to S3."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    oidc.deploy_openid(s3_bucket)
    click.echo("OpenID configuration deployed.")

@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
def print_jwks(iss: str, sub: str, slot: str) -> None:
    """Print JWKS configuration."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    import json
    click.echo(json.dumps(oidc.jwks, indent=2))


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
@click.option("--account", required=True, type=int, help="AWS account ID")
def create_trust_policy(iss: str, sub: str, slot: str, account: int) -> None:
    """Create a trust policy."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    policy = oidc.create_trust_policy(str(account))
    click.echo(policy)


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
@click.option("--rolearn", required=True, type=str, help="AWS role ARN")
@click.option(
    "--duration", required=True, type=int, help="Role assumption duration in seconds"
)
def assume_role(iss: str, sub: str, slot: str, rolearn: str, duration: int) -> None:
    """Assume an AWS role."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    exp = timedelta(seconds=duration)
    credentials: AwsCredentials = oidc.assume_role(rolearn, exp)
    click.echo(credentials)


@cli.command()
@click.option("--iss", required=True, type=str, help="Issuer URL")
@click.option("--sub", required=True, type=str, help="Subject identifier")
@click.option("--slot", required=True, type=str, help="Yubikey slot identifier")
@click.option("--profile", required=True, type=str, help="AWS profile name")
@click.option("--rolearn", required=True, type=str, help="AWS role ARN")
@click.option("--duration", required=True, type=int, help="Session duration in seconds")
def login(
    iss: str, sub: str, slot: str, profile: str, rolearn: str, duration: int
) -> None:
    """Login to AWS."""
    oidc = YubikeyOIDC(iss=iss, sub=sub, slot=slot)
    exp = timedelta(seconds=duration)
    oidc.login_to_aws(profile, rolearn, exp)
    click.echo(f"Logged in to AWS profile ({profile}).")


if __name__ == "__main__":
    cli()
