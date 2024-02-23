import nvdlib

def get_cve_details(cve_id):
    try:
        result = nvdlib.searchCVE(cveId=cve_id)[0]
        severity = result.v31severity
        score = result.v31score
        description = result.descriptions[0].value
        vector = result.v31vector
        return severity, score, description, vector
    except IndexError:
        return None, None, None, None

def main():
    # List of CVEs
    cve_list = ['CVE-2023-48795', 'CVE-2023-46445','CVE-2023-46446']

    for cve_id in cve_list:
        severity, score, description, vector = get_cve_details(cve_id)
        if severity:
            print(f"CVE ID: {cve_id}")
            print(f"Severity: {severity}")
            print(f"Score: {score}")
            print(f"Description: {description}")
            print(f"Vector: {vector}")
            print()

if __name__ == "__main__":
    main()
