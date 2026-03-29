from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic(count=100, timeout=30)

    capture.analyse("tcp")

    summary = capture.get_summary()
    print("\n=== Résumé de l'analyse ===")
    print(summary)

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.title = "Rapport d'analyse du trafic réseau"
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    logger.info(f"Rapport généré : {filename}")


if __name__ == "__main__":
    main()