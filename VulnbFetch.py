import requests
from datetime import datetime, timedelta
import pandas as pd

end_date = datetime.now()
start_date = end_date - timedelta(days=1)

pub_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
pub_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# NVD CVE API endpoint
nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start_date}&pubEndDate={pub_end_date}"

def get_json_response(url):
    response = requests.get(url)
    return response.json()

def get_cve_details():
    data = get_json_response(nvd_api_url)
    cve_items = data.get('vulnerabilities', [])
    cve_list = []

    for item in cve_items:
        cve = item.get('cve', {})
        cve_id = cve.get('id')

        cvss_v3_metrics = cve.get('metrics', {}).get('cvssMetricV31', [])
        if not cvss_v3_metrics:
            cvss_v3_metrics = cve.get('metrics', {}).get('cvssMetricV30', [])

        base_score = None
        severity = None
        exploitability_score = None
        impact_score = None

        if cvss_v3_metrics:
            cvss_v3 = cvss_v3_metrics[0]
            base_score = cvss_v3.get('cvssData', {}).get('baseScore')
            severity = cvss_v3.get('cvssData', {}).get('baseSeverity')
            exploitability_score = cvss_v3.get('exploitabilityScore')
            impact_score = cvss_v3.get('impactScore')

        description_data = cve.get('descriptions', [{}])
        description = description_data[0].get('value', 'No description available')

        references_data = cve.get('references', [])
        references = [ref.get('url') for ref in references_data]

        published_date = cve.get('published', 'Unknown')[:10]

        # Get EPSS score
        epss_api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        epss_data = get_json_response(epss_api_url)
        epss_score = 'Not available'
        if 'data' in epss_data and epss_data['data']:
            epss_score = epss_data['data'][0].get('epss', 'Not available')

        cve_list.append({
            'cve_id': cve_id,
            'base_score': base_score,
            'severity': severity,
            'description': description,
            'references': references,
            'published_date': published_date,
            'epss_score': epss_score,
            'exploitability_score': exploitability_score,
            'impact_score': impact_score
        })

    return sorted(cve_list, key=lambda x: (x['base_score'] is not None, x['base_score']), reverse=True)

def print_cve_details(cve_list):
    for cve_item in cve_list:
        print(f"CVE ID: {cve_item['cve_id']}")
        print(f"CVSS v3 Base Score: {cve_item['base_score']}")
        print(f"Severity: {cve_item['severity']}")
        print(f"Description: {cve_item['description']}")
        print(f"Published Date: {cve_item['published_date']}")
        print(f"EPSS Score: {cve_item['epss_score']}")
        print(f"Exploitability Score: {cve_item['exploitability_score']}")
        print(f"Impact Score: {cve_item['impact_score']}")
        print("References:")
        for ref in cve_item['references']:
            print(f" - {ref}")
        print("-" * 40)

def main():
    cve_list_sorted = get_cve_details()
    print_cve_details(cve_list_sorted)

    download_choice = input("Do you want to download an Excel file with all CVE details? (Y/y for yes, N/n for no): ").lower()
    if download_choice == 'y':
        df = pd.DataFrame(cve_list_sorted)
        file_name = "CVE_Details.xlsx"
        df.to_excel(file_name, index=False)
        print(f"Excel file '{file_name}' has been successfully created and downloaded.")
    elif download_choice == 'n':
        print("Exiting program.")
    else:
        print("Invalid choice. Exiting program.")

if __name__ == "__main__":
    main()
