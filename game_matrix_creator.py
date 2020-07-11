from cvss import CVSS3
import math
import pprint

pp = pprint.PrettyPrinter(indent=4)


def get_cvss_scores(cvss_vectors):
    # Format: 'CVE' : (Modified IS, Modified ES, Overall Score)
    max_impact = -math.inf
    cvss_scores = {}
    for cve in cvss_vectors:
        c = CVSS3(cvss_vectors[cve][1])
        scores = [
            round(c.modified_isc, 1),
            round(c.modified_esc * c.temporal_score / c.base_score, 1),
            round(c.environmental_score, 1),
        ]
        max_impact = float(scores[0]) if max_impact < scores[0] else max_impact
        cvss_scores[cve] = tuple(map(float, scores))
    # pp.pprint(cvss_scores)
    return cvss_scores, max_impact


def get_hp_info_gain(cvss_vectors, attack_type_info, max_impact=10):
    honeypatch_profit = {}
    num_types = len(attack_type_info)
    for cve in cvss_vectors:
        honeypatch_profit[cve] = 0.0
        types = cvss_vectors[cve][0]
        for t in types:
            honeypatch_profit[cve] += (
                max_impact * (attack_type_info.index(t.upper()) + 1) / num_types
            )
    # pp.pprint(honeypatch_profit)
    return honeypatch_profit


def get_exploit_available_attacks(cvss_vectors):
    exp_available_checks = ["E:F", "E:H"]  # 'E:P'
    available_exploits = []
    for cve in cvss_vectors:
        vector = cvss_vectors[cve][1]
        is_exp_available = any([x in vector for x in exp_available_checks])
        if is_exp_available:
            available_exploits.append(cve)
    print('{}/{} : {}'.format(len(available_exploits), len(cvss_vectors.keys()), available_exploits))
    return available_exploits


def run():
    cvss_vectors = {
        "CVE-2014-0160": (
            ["IL"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C/CR:H/IR:X/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:N/MA:N",
        ),
        "CVE-2012-1823": (
            ["SH"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:H/RL:O/RC:C/CR:M/IR:M/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:L/MA:L",
        ),
        "CVE-2011-3368": (
            ["PS"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C/CR:M/IR:X/AR:X/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:L/MI:N/MA:N",
        ),
        "CVE-2014-6271": (
            ["SH"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H",
        ),
        "CVE-2014-0224": (
            ["SH", "IL"],
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:O/RC:C/CR:H/IR:H/AR:X/MAV:N/MAC:H/MPR:N/MUI:N/MS:X/MC:H/MI:H/MA:X",
        ),
        "CVE-2010-0740": (
            ["DoS"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:L",
        ),
        "CVE-2010-1452": (
            ["DoS"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:O/RC:C/CR:X/IR:X/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:X",
        ),
        "CVE-2016-6515": (
            ["DoS"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:N/MI:N/MA:H",
        ),
        "CVE-2016-7054": (
            ["DoS"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H/RL:O/RC:C/CR:X/IR:X/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:X/MC:X/MI:X/MA:H",
        ),
        "CVE-2017-5941": (
            ["SH"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H",
        ),
        "CVE-2017-7494": (
            ["SH"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:H/IR:H/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H",
        ),
    }
    type_ordering = ["DOS", "PS", "IL", "SH"]
    patchsets_to_attacks = {
        1: ["CVE-2014-0160", "CVE-2014-0224"],
        2: ["CVE-2012-1823", "CVE-2014-6271", "CVE-2017-5941", "CVE-2017-7494"],
        3: ["CVE-2011-3368"],
        4: ["CVE-2010-0740", "CVE-2010-1452", "CVE-2016-6515", "CVE-2016-7054"],
    }
    cvss_scores, max_impact = get_cvss_scores(cvss_vectors)
    hp_info = get_hp_info_gain(cvss_vectors, type_ordering, max_impact)

    e1 = get_exploit_available_attacks(cvss_vectors)


if __name__ == "__main__":
    run()
