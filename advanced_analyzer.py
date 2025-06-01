from dns_tun_module import DNSTunnelDetector
from report_generator_v2 import ReportGenerator
from CONFIG_INFO import *

if __name__ == "__main__":
    generator = ReportGenerator()
    result_file = DNSTunnelDetector.cron_analysis()
    print(f"Analysis completed. Results saved to {result_file}")
    # result_file = "/home/alex/Coding/FuzzySystem/pcaps/dns/TEST_CRON/RES/dns_analysis_20250522_1635.json"
    generator.generate_report(DNS_TUN, result_file)