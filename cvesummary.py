import openpyxl
import nvdlib

def read_cves_from_textfile(filename):
    cve_list = [] 
    with open(filename, 'r') as file:
        for line in file:
            cve_list.append(line.strip())
    return cve_list


def read_cves_from_excel(excel_file):
    cve_list = []
    workbook = openpyxl.load_workbook(excel_file)
    sheet = workbook.active
    for row in sheet.iter_rows(values_only=True):
        cve_list.extend(row)
    return cve_list

def get_cve_details(cve_id):
    try:
        result = nvdlib.searchCVE(cveId=cve_id)[0]
        score = result.score
        description = result.descriptions[0].value
        return score, description
    except IndexError:
        return None, None 

def main():
    # Initialize CVE list
    #cve_list = ['CVE-2024-21892', 'CVE-2023-41993', 'CVE-2024-20954', 'CVE-2024-21098', 'CVE-2024-21085', 'CVE-2024-21011',  'CVE-2024-21068','CVE-2024-21094','CVE-2024-21012','CVE-2024-21003','CVE-2024-21004','CVE-2024-21002']
    cve_list = read_cves_from_textfile('cves.txt')

    for cve_id in cve_list:
        #severity, score, description, vector = get_cve_details(cve_id)
        score, description = get_cve_details(cve_id)  
        if score:
            print(f"CVE ID: {cve_id}")
            print (f"Score: {score}")
            print(f"Description: {description}")

if __name__ == "__main__":
    main()
