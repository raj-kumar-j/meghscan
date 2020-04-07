
import subprocess
from dictor import dictor as dt
import json
from services import s3


def run_cmd(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE,)
    stdout, stderr = proc.communicate()

    return proc.returncode, stdout.decode('utf-8'), stderr.decode('utf-8').strip()


def run_checks(trusted_acc_ids):

    table_data = [['S.No','Title','Impact','Description','Affected Bucket(s)','Reference']]

    print("\n[*] Checking S3 for missing security best practices now....\n")
    print(f"[*] Total Checks to perform : {s3.total_checks}\n")

    if len(trusted_acc_ids) == 0:
        print("[!] Trusted accound ids were not provided. S3 Cross account access check will not be performed.\n")

    # ------------------------------------------------------------------------------------------------------------------------------------

    ret_c, output, error = run_cmd(
        ["aws", "s3api", "list-buckets", "--query", "Buckets[*].Name"])
    blist = (((((output.replace("[", "")).replace(']', '')).replace(
        '"', '')).replace('\n', '')).replace(' ', '')).split(',')
    print(f"\t[*] Total Buckets found: {len(blist)}\n")

    # ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t1.{s3.check1Title} ({s3.check1Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-acl", "--output", "json", "--bucket", blist[bucket]])

        if ret_c == 0:
            Grants = dt(json.loads(output), 'Grants')

            search_URI = ["http://acs.amazonaws.com/groups/global/AllUsers",
                          "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
            search_PERM = ['WRITE_ACP', 'READ_ACP', 'WRITE', 'READ']

            for i in range(0, len(Grants)):
                URI = dt(Grants, f"{i}.Grantee.URI")
                PERM = dt(Grants, f"{i}.Permission")
                if (URI in search_URI) and (PERM in search_PERM):
                    s3.impacted_buckets[0].append(blist[bucket])

                    break
        else:
            print(f"Check failed with error : {error} ")


    table_data.append(['1', s3.check1Title, s3.check1Impact, s3.check1Desc, ','.join(s3.impacted_buckets[0]), s3.check1Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[0])}                                      \n")

    # ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t2.{s3.check2Title} ({s3.check2Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-policy", "--bucket", blist[bucket], "--output", "text", "--query", "Policy"])


        if ret_c == 0:
            stmts = dt(json.loads(output), 'Statement')
            for i in range(0, len(stmts)):
                effect = dt(stmts, f"{i}.Effect")
                principal = dt(stmts, f"{i}.Principal")
                principal_aws = dt(stmts, f"{i}.Principal.AWS")
                if (effect == "Allow") and (principal == "*" or principal_aws == "*"):
                    s3.impacted_buckets[1].append(blist[bucket])
                    break

            # Checking for S3 cross account to save time, cpu and aws api calls
            if len(trusted_acc_ids) > 0:
                found_ids = []

                for i in range(0, len(stmts)):
                    effect = dt(stmts, f"{i}.Effect")
                    if effect == "Allow":
                        ids = dt(stmts, f"{i}.Principal.AWS")
                        for j in range(0, len(ids)):
                            found_ids.append(ids[j].split(':')[4])

                if len(found_ids) > 0:
                    for id in found_ids:
                        if not id in trusted_acc_ids:
                            s3.impacted_buckets[3].append(blist[bucket])
                            break

                            # Checking for S3 cross account and Server Side Encryption to save time, cpu and aws api calls
            for i in range(0, len(stmts)):
                secureTransport = dt(
                    stmts, f"{i}.Condition.Bool.aws:SecureTransport")
                effect = dt(stmts, f"{i}.Effect")

                if (effect == "Allow") and (secureTransport == "false"):
                    s3.impacted_buckets[5].append(blist[bucket])

                    break

                elif (effect == "Deny") and (secureTransport == "true"):
                    s3.impacted_buckets[5].append(blist[bucket])

                    break

            for i in range(0, len(stmts)):
                sse = dt(
                    stmts, f"{i}.Condition.Null.s3:x-amz-server-side-encryption")

                if sse != "true":
                    s3.impacted_buckets[7].append(blist[bucket])

                    break


        else:
            print(f"Check failed with error : {error} ")

    table_data.append(['2', s3.check2Title, s3.check2Impact, s3.check2Desc, ','.join(s3.impacted_buckets[1]), s3.check2Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[1])}                                      \n")

    # ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t3.{s3.check3Title} ({s3.check3Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-encryption", "--bucket", blist[bucket]])
        if "ServerSideEncryptionConfigurationNotFoundError" in error:
            s3.impacted_buckets[2].append(blist[bucket])

    table_data.append(['3', s3.check3Title, s3.check3Impact, s3.check3Desc, ','.join(s3.impacted_buckets[2]), s3.check3Reference])

    print(f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[2])}                                      \n")

    # ------------------------------------------------------------------------------------------------------------------------------------

    if len(trusted_acc_ids) > 0:
        print(f"\t4.{s3.check4Title} ({s3.check4Impact})")

        table_data.append(['4', s3.check4Title, s3.check4Impact, s3.check4Desc, ','.join(s3.impacted_buckets[3]), s3.check4Reference])

        print(
            f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[3])}                                      \n")
    else:
        table_data.append(['4', s3.check4Title, s3.check4Impact, s3.check4Desc,
            'Check not performed. Trusted account ids were not provided.', s3.check4Reference])

    # ------------------------------------------------------------------------------------------------------------------------------------
    print(f"\t5.{s3.check5Title} ({s3.check5Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-logging", "--bucket", blist[bucket]])
        if not "LoggingEnabled" in output:
            s3.impacted_buckets[4].append(blist[bucket])

    table_data.append(['5', s3.check5Title, s3.check5Impact, s3.check5Desc, ','.join(s3.impacted_buckets[4]), s3.check5Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[4])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t6.{s3.check6Title} ({s3.check6Impact})")

    table_data.append(['6', s3.check6Title, s3.check6Impact, s3.check6Desc, ','.join(s3.impacted_buckets[5]), s3.check6Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[5])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t7.{s3.check7Title} ({s3.check7Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-website", "--bucket", blist[bucket]])

        if ret_c != 0:
            if "NoSuchWebsiteConfiguration" in error:
                pass
        else:
            s3.impacted_buckets[6].append(blist[bucket])

    table_data.append(['7', s3.check7Title, s3.check7Impact, s3.check7Desc, ','.join(s3.impacted_buckets[6]), s3.check7Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[6])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t8.{s3.check8Title} ({s3.check8Impact})")

    table_data.append(['8', s3.check8Title, s3.check8Impact, s3.check8Desc, ','.join(s3.impacted_buckets[7]), s3.check8Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[7])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t9.{s3.check9Title} ({s3.check9Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-versioning", "--bucket", blist[bucket]])

        if ret_c == 0:
            if not "Enabled" in output:
                s3.impacted_buckets[8].append(blist[bucket])

        else:
            print(
                f"\t\t[!] Check failed on bucket '{blist[bucket]}' with error: {error}\n")

    table_data.append(['9', s3.check9Title, s3.check9Impact, s3.check9Desc, ','.join(s3.impacted_buckets[8]), s3.check9Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[8])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t10.{s3.check10Title} ({s3.check10Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-bucket-lifecycle-configuration", "--bucket", blist[bucket]])

        if ret_c != 0:
            if "NoSuchLifecycleConfiguration" in error:
                s3.impacted_buckets[9].append(blist[bucket])
            else:
                print(
                    f"\t\t[!] Check failed on bucket '{blist[bucket]}' with error: {error}\n")

    table_data.append(['10', s3.check10Title, s3.check10Impact, s3.check10Desc, ','.join(s3.impacted_buckets[9]), s3.check10Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[9])}                                      \n")
# ------------------------------------------------------------------------------------------------------------------------------------

    print(f"\t11.{s3.check11Title} ({s3.check11Impact})")
    for bucket in range(0, len(blist)):
        print(
            f"\t\t[*] Checking bucket {bucket+1} : {blist[bucket]}                                                    ", end='\r')
        ret_c, output, error = run_cmd(
            ["aws", "s3api", "get-object-lock-configuration", "--bucket", blist[bucket]])

        if ret_c != 0:
            if "ObjectLockConfigurationNotFoundError" in error:
                s3.impacted_buckets[10].append(blist[bucket])
            else:
                print(
                    f"\t\t[!] Check failed on bucket '{blist[bucket]}' with error: {error}\n")

    table_data.append(['11', s3.check11Title, s3.check11Impact, s3.check11Desc, ','.join(s3.impacted_buckets[10]), s3.check11Reference])

    print(
        f"\t\t[*] Total No. of Affected Buckets : {len(s3.impacted_buckets[10])}                                      \n")

# ------------------------------------------------------------------------------------------------------------------------------------

    return table_data


