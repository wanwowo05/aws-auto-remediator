import boto3
from rich.console import Console
from rich.table import Table

console = Console()
dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-1")
table = dynamodb.Table("CloudAutoRemediatorAudit")


def main():
    response = table.scan()
    items = response.get("Items", [])
    items.sort(key=lambda x: x["Timestamp"], reverse=True)

    ui_table = Table(
        title="AWS Cloud Security & FinOps Remediation Logs", show_lines=True
    )
    ui_table.add_column("Timestamp (UTC)", style="cyan")
    ui_table.add_column("Resource ID", style="magenta", bold=True)
    ui_table.add_column("Violation", style="yellow")
    ui_table.add_column("Action Taken", style="green")
    ui_table.add_column("IAM User / Role", style="dim")

    for item in items:
        ui_table.add_row(
            item.get("Timestamp", "")[:19],
            item.get("ResourceId", ""),
            item.get("Violation", ""),
            item.get("ActionTaken", ""),
            item.get("ViolatingUser", "").split("/")[-1],
        )

    console.print(ui_table)


if __name__ == "__main__":
    main()
