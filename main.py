import argparse
import logging
from indexer.indexer import ASTIndexer
from analyzer.analyzer import TaintAnalyzer
from reporter.reporter import SARIFReporter

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Custom SAST Tool")
    parser.add_argument("path", help="Path to the codebase directory")
    parser.add_argument("--rules", default="rules/rules.yaml", help="Path to rules file")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize components
        logger.info("Initializing AST indexer...")
        indexer = ASTIndexer()

        # Index the codebase
        logger.info(f"Indexing codebase: {args.path}")
        indexer.index_project(args.path)

        # Load analysis rules
        logger.info(f"Loading rules from: {args.rules}")
        rules = indexer.load_rules(args.rules)

        # Perform taint analysis
        logger.info("Running taint analysis...")


        findings = indexer.generate_sarif_findings(args.path)

        # Generate SARIF report
        logger.info("Generating SARIF report...")
        reporter = SARIFReporter()
        report = reporter.generate_report(findings, args.path)

        print(report)
        # # analyzer = TaintAnalyzer(indexer.symbol_table, indexer.data_flows)
        # analyzer = TaintAnalyzer(indexer.tainted_vars, indexer.data_flows)
        # findings = analyzer.analyze(rules)

        # # Generate SARIF report
        # logger.info("Generating SARIF report...")
        # reporter = SARIFReporter()
        # report = reporter.generate_report(findings, args.path)

        # print(report)

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=args.debug)

if __name__ == "__main__":
    main()