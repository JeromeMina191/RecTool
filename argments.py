import argparse


def setarguments():
    parser = argparse.ArgumentParser(description="ReconTool Do all work for you")
    parser.add_argument('-w', '--website',dest='website', type=str,help='set website -w example.com')
    parser.add_argument('-p', '--place', dest='place', type=str, help='set place -p /path')
    parser.add_argument('-t', '--telegram', dest='telegram',action='store_true',help='send telegram message with the results')
    parser.add_argument('-api', '--api', dest='api',action='store_true',help='This make you add Apis')

    args = parser.parse_args()
    return args
