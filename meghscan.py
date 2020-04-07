
import argparse
from services import s3_check
import datetime

parser = argparse.ArgumentParser(description='AWS security best practices check')

parser.add_argument('service', type=str, choices=['s3'],
    help='aws service to check for. currently only s3 is allowed.')

parser.add_argument(
    '--trusted_ids',
    help='List of trusted 12 digit AWS account ids to check for any cross account access. Ids must be comma separated.',
    default="None", type=str)

parser.add_argument('-html', action='store_true', help="Save results in html file.")

args = parser.parse_args()

def make_html(table_data):

    for row in table_data:
        yield '  <tr><td>'
        yield '    </td><td>'.join(row)
        yield '  </td></tr>'


if args.service == 's3':
    trusted_acc_ids = []

    if not args.trusted_ids == "None":
        trusted_acc_ids = args.trusted_ids.split(',')

    output = s3_check.run_checks(trusted_acc_ids)

if args.html:
    results = '\n'.join(make_html(output))

    html_code_top =  f"""
    <!DOCTYPE html>
    <html>
    <body bgcolor="#F4F4F4">
    <h2>AWS {(args.service).upper()} Security best practices results.</h2>
    <table style="width:90%" bgcolor="white" align="center" border="1">
    """

    html_code_bottom = """
    </table>
    </body>
    </html>
    """

    data = html_code_top+results+html_code_bottom

    filename = "vyas-"+args.service+"-results-"+str(datetime.date.today())+".html"

    with open(filename, 'wt') as file:
        file.write(data)



exit(0)

