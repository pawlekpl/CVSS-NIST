import requests
import json
import numpy as np
import matplotlib.pyplot as plt

# lista wyników bazowych CVSS 3.1
base_scores = []

# pobranie danych CVE ze strony NIST
for x in range(0, 209691, 2000):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=2000&startIndex={x}"
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
        vulnerabilities = data['result']['CVE_Items']
        for vulnerability in vulnerabilities:
            cvss_v31 = vulnerability['impact'].get('baseMetricV3', {}).get('cvssV3', {})
            if cvss_v31:
                base_score = cvss_v31.get('baseScore')
                if base_score:
                    base_scores.append(base_score)

# obliczenie, ile kombinacji flag odwzorowuje każdą wartość wyniku bazowego CVSS 3.1
x_values = np.arange(0, 10.1, 0.1)
base_scores_dict = {}
for x in x_values:
    count = 0
    for base_score in base_scores:
        if round(base_score, 1) == round(x, 1):
            count += 1
    base_scores_dict[x] = count

# generowanie histogramu
plt.bar(list(base_scores_dict.keys()), base_scores_dict.values(), color='g', width=0.1)
plt.xlabel('Wynik bazowy CVSS 3.1')
plt.ylabel('Liczba kombinacji flag')
plt.title('Histogram liczby kombinacji flag w CVSS 3.1')
plt.show()

