import io
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, Image
)


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph
        return content

    def save(self, filename: str) -> None:
        with open(filename, "w") as f:
            f.write(self.concat_report())

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=20,
            spaceAfter=12,
            textColor=colors.HexColor("#1a1a2e"),
        )
        story.append(Paragraph(self.title, title_style))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Analyse du trafic", styles["Heading2"]))
        story.append(Spacer(1, 0.3 * cm))

        for line in self.summary.split("\n"):
            if line.strip():
                story.append(Paragraph(line, styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

        protocols = self.capture.sort_network_protocols()
        if protocols:
            story.append(Paragraph("Tableau des protocoles capturés", styles["Heading2"]))
            story.append(Spacer(1, 0.3 * cm))

            table_data = [["Protocole", "Nombre de paquets"]]
            for proto, count in protocols.items():
                table_data.append([proto, str(count)])

            table = Table(table_data, colWidths=[8 * cm, 8 * cm])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.8 * cm))

        if protocols:
            story.append(Paragraph("Graphique des protocoles", styles["Heading2"]))
            story.append(Spacer(1, 0.3 * cm))

            fig, ax = plt.subplots(figsize=(7, 4))
            ax.bar(
                list(protocols.keys()),
                list(protocols.values()),
                color="#4e79a7",
                edgecolor="white",
            )
            ax.set_title("Paquets capturés par protocole", fontsize=13)
            ax.set_xlabel("Protocole")
            ax.set_ylabel("Nombre de paquets")
            ax.tick_params(axis="x", rotation=15)
            plt.tight_layout()

            buf = io.BytesIO()
            plt.savefig(buf, format="png", dpi=150)
            plt.close(fig)
            buf.seek(0)

            img = Image(buf, width=14 * cm, height=8 * cm)
            story.append(img)

        doc.build(story)
        print(f"\n[+] Rapport PDF généré : {filename}")

    def generate(self, param: str) -> None:
        if param == "graph":
            self.graph = ""
        elif param == "array":
            self.array = ""