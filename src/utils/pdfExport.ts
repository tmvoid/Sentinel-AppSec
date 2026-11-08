import { jsPDF } from 'jspdf';
import type { AuditReport } from '../types/audit.ts';

/**
 * Sanitizes text for standard PDF PostScript fonts (Helvetica/Courier)
 * and inserts soft wrap opportunities inside ultra-long unbroken tokens/URLs
 * so text never overflows the right margin.
 */
function sanitizeAndSoftBreak(raw: string): string {
  return raw
    .replace(/·/g, '|')
    .replace(/—/g, '-')
    .replace(/–/g, '-')
    .replace(/→/g, '->')
    .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, '')
    .split('\n')
    .map((line) =>
      line.replace(/(\S{58})(?=\S)/g, '$1 ')
    )
    .join('\n');
}

/**
 * Sets the exact font and size BEFORE calling splitTextToSize so jsPDF
 * calculates character widths accurately and respects exact right margins.
 */
function wrapTextExact(
  doc: jsPDF,
  text: string,
  fontName: 'helvetica' | 'courier',
  fontStyle: 'normal' | 'bold',
  fontSize: number,
  maxWidth: number
): string[] {
  doc.setFont(fontName, fontStyle);
  doc.setFontSize(fontSize);
  const cleaned = sanitizeAndSoftBreak(text);
  return doc.splitTextToSize(cleaned, maxWidth) as string[];
}

function loadLogoImage(): Promise<HTMLImageElement | null> {
  return new Promise((resolve) => {
    try {
      if (typeof window === 'undefined' || typeof Image === 'undefined') {
        resolve(null);
        return;
      }
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => resolve(img);
      img.onerror = () => resolve(null);
      img.src = '/assets/aistudio/Code_Generated_Image_dcad87d9.png';
    } catch {
      resolve(null);
    }
  });
}

/**
 * Generates and downloads a multi-page vector PDF security audit certificate
 * with strict 48pt (17mm) print margins on all sides and a subtle vector security watermark.
 */
export async function exportAuditReportToPdf(report: AuditReport): Promise<void> {
  const logoImg = await loadLogoImage();
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  // A4 in pt: 595.28 x 841.89
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const MARGIN_X = 48; // 48pt (~17mm) left & right margin
  const MARGIN_TOP = 48; // 48pt top margin
  const MARGIN_BOTTOM = 56; // 56pt bottom margin (includes footer)
  const CONTENT_WIDTH = pageWidth - MARGIN_X * 2; // 499.28pt
  const CARD_PAD = 14;
  const INNER_TEXT_WIDTH = CONTENT_WIDTH - CARD_PAD * 2; // 471.28pt

  const stampSentinelWatermark = () => {
    try {
      const cx = pageWidth / 2;
      const cy = pageHeight / 2 + 15;
      // High-precision vector geometric security shield watermark
      doc.setDrawColor(234, 240, 248);
      doc.setLineWidth(1.5);
      const w = 210;
      const h = 260;
      // Outer subtle shield boundary
      doc.lines(
        [
          [w / 2, -28],
          [w / 2, 28],
          [0, h * 0.46],
          [-w / 2, h * 0.54],
          [-w / 2, -h * 0.54],
          [0, -h * 0.46],
        ],
        cx - w / 2,
        cy - h / 2,
        [1, 1],
        'D',
        true
      );
    } catch {
      // ignore
    }
  };

  let y = MARGIN_TOP;

  const ensureSpace = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - MARGIN_BOTTOM) {
      doc.addPage();
      y = MARGIN_TOP;
    }
  };

  // =========================================================================
  // 1. HEADER CARD (Strictly Respecting 48pt Top, Left, and Right Margins)
  // =========================================================================
  const headerHeight = 96;
  doc.setFillColor(10, 17, 32);
  doc.setDrawColor(0, 120, 212);
  doc.setLineWidth(1);
  doc.roundedRect(MARGIN_X, y, CONTENT_WIDTH, headerHeight, 6, 6, 'FD');

  // Accent bar inside bottom of header card
  doc.setFillColor(0, 120, 212);
  doc.rect(MARGIN_X + 2, y + headerHeight - 3, CONTENT_WIDTH - 4, 3, 'F');

  // Geometric Sentinel Crest Badge
  const badgeSize = 52;
  const badgeX = MARGIN_X + 16;
  const badgeY = y + (headerHeight - badgeSize) / 2;

  let logoDrawn = false;
  if (logoImg) {
    try {
      doc.addImage(logoImg, 'PNG', badgeX, badgeY, badgeSize, badgeSize);
      logoDrawn = true;
    } catch {
      logoDrawn = false;
    }
  }

  if (!logoDrawn) {
    doc.setFillColor(14, 28, 54);
    doc.setDrawColor(0, 120, 212);
    doc.setLineWidth(1.2);
    doc.roundedRect(badgeX, badgeY, badgeSize, badgeSize, 8, 8, 'FD');

    // Vector Shield Icon Inside Badge
    doc.setDrawColor(56, 189, 248);
    doc.setLineWidth(1.8);
    const sw = 22;
    const sh = 28;
    const scx = badgeX + badgeSize / 2;
    const scy = badgeY + badgeSize / 2;
    doc.lines(
      [
        [sw / 2, -3],
        [sw / 2, 3],
        [0, sh * 0.44],
        [-sw / 2, sh * 0.56],
        [-sw / 2, -sh * 0.56],
        [0, -sh * 0.44],
      ],
      scx - sw / 2,
      scy - sh / 2,
      [1, 1],
      'D',
      true
    );
  }

  const headerTextX = badgeX + badgeSize + 16;
  const headerMaxTextW = pageWidth - MARGIN_X - 16 - headerTextX;

  doc.setTextColor(76, 194, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.text(
    'SENTINEL APPSEC  |  APPLICATION SECURITY VERIFICATION',
    headerTextX,
    y + 24
  );

  const titleLines = wrapTextExact(
    doc,
    report.projectName || 'Sentinel Application Security Verification Report',
    'helvetica',
    'bold',
    14,
    headerMaxTextW
  );
  doc.setTextColor(255, 255, 255);
  doc.text(titleLines[0], headerTextX, y + 43);

  const metaLine1 = wrapTextExact(
    doc,
    `Report ID: ${report.id}  |  Duration: ${report.durationMs} ms`,
    'courier',
    'normal',
    8,
    headerMaxTextW
  );
  doc.setTextColor(180, 196, 220);
  doc.text(metaLine1[0], headerTextX, y + 60);

  const targetSummaryStr = [
    `Date: ${new Date(report.timestamp).toUTCString()}`,
    report.targetSummary.targetUrl ? `URL: ${report.targetSummary.targetUrl}` : '',
    report.targetSummary.githubRepoUrl
      ? `Repo: ${report.targetSummary.githubRepoUrl}`
      : '',
  ]
    .filter(Boolean)
    .join('  |  ');

  const metaLine2 = wrapTextExact(
    doc,
    targetSummaryStr,
    'courier',
    'normal',
    7.5,
    headerMaxTextW
  );
  doc.setTextColor(148, 163, 184);
  doc.text(metaLine2[0], headerTextX, y + 75);

  y += headerHeight + 18;

  // =========================================================================
  // 2. QUANTITATIVE SEVERITY & POSTURE STRIP (Within 48pt Margins)
  // =========================================================================
  const criticalCount = report.findings.filter((f) => f.severity === 'critical').length;
  const highCount = report.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = report.findings.filter((f) => f.severity === 'medium').length;
  const lowCount = report.findings.filter((f) => f.severity === 'low').length;

  const gap = 8;
  const boxWidth = (CONTENT_WIDTH - gap * 4) / 5;
  const metrics = [
    { label: 'CRITICAL', value: String(criticalCount), color: [220, 38, 38] as [number, number, number] },
    { label: 'HIGH', value: String(highCount), color: [234, 88, 12] as [number, number, number] },
    { label: 'MEDIUM', value: String(mediumCount), color: [202, 138, 4] as [number, number, number] },
    { label: 'LOW', value: String(lowCount), color: [2, 132, 199] as [number, number, number] },
    { label: 'PASSED', value: String(report.passedChecks.length), color: [22, 163, 74] as [number, number, number] },
  ];

  metrics.forEach((m, i) => {
    const bx = MARGIN_X + i * (boxWidth + gap);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.75);
    doc.roundedRect(bx, y, boxWidth, 46, 4, 4, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(m.label, bx + 10, y + 16);

    doc.setFont('courier', 'bold');
    doc.setFontSize(15);
    doc.setTextColor(m.color[0], m.color[1], m.color[2]);
    doc.text(m.value, bx + 10, y + 36);
  });

  y += 64;

  // =========================================================================
  // 3. EXECUTIVE VERIFICATION SUMMARY
  // =========================================================================
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('1. Executive Verification Summary', MARGIN_X, y);
  y += 14;

  const execSummaryText =
    report.findings.length === 0
      ? 'All enabled deterministic security verification engines completed with 0 exploitable vulnerabilities detected. Every finding in Sentinel AppSec requires empirical proof; no synthetic warnings are generated.'
      : `The Sentinel AppSec engine verified ${report.findings.length} security finding(s) backed by empirical HTTP header responses, SPA-filtered sensitive route probes, live OSV.dev CVE advisories, or exact source code line matches, alongside ${report.passedChecks.length} passed security control(s).`;

  const execLines = wrapTextExact(
    doc,
    execSummaryText,
    'helvetica',
    'normal',
    9.5,
    CONTENT_WIDTH
  );
  doc.setTextColor(51, 65, 85);
  doc.text(execLines, MARGIN_X, y);
  y += execLines.length * 13 + 16;

  // =========================================================================
  // 4. EMPIRICAL VULNERABILITY LEDGER
  // =========================================================================
  ensureSpace(44);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(
    `2. Empirical Vulnerability Ledger (${report.findings.length})`,
    MARGIN_X,
    y
  );
  y += 14;

  if (report.findings.length === 0) {
    doc.setFillColor(240, 253, 244);
    doc.setDrawColor(187, 247, 208);
    doc.roundedRect(MARGIN_X, y, CONTENT_WIDTH, 34, 4, 4, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(21, 128, 61);
    doc.text(
      'VERIFIED CLEAN -- Zero exploitable vulnerabilities detected across all active engines.',
      MARGIN_X + CARD_PAD,
      y + 21
    );
    y += 50;
  } else {
    report.findings.forEach((f, idx) => {
      // Measure all wrapped text lines BEFORE calculating card height!
      const titleLinesArr = wrapTextExact(
        doc,
        `${String(idx + 1).padStart(2, '0')}. [${f.severity.toUpperCase()}] ${f.title}`,
        'helvetica',
        'bold',
        9.5,
        INNER_TEXT_WIDTH
      );
      const metaLinesArr = wrapTextExact(
        doc,
        `${f.cwe}  |  ${f.owasp}  |  Target: ${f.affectedTarget}`,
        'courier',
        'normal',
        8,
        INNER_TEXT_WIDTH
      );
      const summaryLinesArr = wrapTextExact(
        doc,
        `Summary: ${f.summary}`,
        'helvetica',
        'normal',
        8.5,
        INNER_TEXT_WIDTH
      );
      const impactLinesArr = wrapTextExact(
        doc,
        `Impact: ${f.impact}`,
        'helvetica',
        'normal',
        8.5,
        INNER_TEXT_WIDTH
      );
      const proofLinesArr = wrapTextExact(
        doc,
        f.evidence.rawProof,
        'courier',
        'normal',
        7.5,
        INNER_TEXT_WIDTH - 16
      ).slice(0, 8);
      const fixLinesArr = wrapTextExact(
        doc,
        `Remediation: ${f.remediation.summary}`,
        'helvetica',
        'bold',
        8.5,
        INNER_TEXT_WIDTH
      );

      const proofBoxHeight = proofLinesArr.length * 10 + 14;
      const cardHeight =
        CARD_PAD +
        titleLinesArr.length * 12 +
        4 +
        metaLinesArr.length * 10 +
        6 +
        summaryLinesArr.length * 11 +
        4 +
        impactLinesArr.length * 11 +
        8 +
        proofBoxHeight +
        8 +
        fixLinesArr.length * 11 +
        CARD_PAD;

      ensureSpace(cardHeight + 12);

      // Draw Card Container strictly inside [MARGIN_X, MARGIN_X + CONTENT_WIDTH]
      doc.setFillColor(250, 251, 253);
      doc.setDrawColor(203, 213, 225);
      doc.setLineWidth(0.75);
      doc.roundedRect(MARGIN_X, y, CONTENT_WIDTH, cardHeight, 4, 4, 'FD');

      let cy = y + CARD_PAD + 8;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(15, 23, 42);
      doc.text(titleLinesArr, MARGIN_X + CARD_PAD, cy);
      cy += titleLinesArr.length * 12 + 4;

      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(71, 85, 105);
      doc.text(metaLinesArr, MARGIN_X + CARD_PAD, cy);
      cy += metaLinesArr.length * 10 + 6;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      doc.text(summaryLinesArr, MARGIN_X + CARD_PAD, cy);
      cy += summaryLinesArr.length * 11 + 4;

      doc.text(impactLinesArr, MARGIN_X + CARD_PAD, cy);
      cy += impactLinesArr.length * 11 + 6;

      // Proof Box
      doc.setFillColor(15, 23, 42);
      doc.roundedRect(
        MARGIN_X + CARD_PAD,
        cy - 6,
        INNER_TEXT_WIDTH,
        proofBoxHeight,
        3,
        3,
        'F'
      );
      doc.setFont('courier', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(226, 232, 240);
      doc.text(proofLinesArr, MARGIN_X + CARD_PAD + 8, cy + 5);
      cy += proofBoxHeight + 8;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(21, 128, 61);
      doc.text(fixLinesArr, MARGIN_X + CARD_PAD, cy);

      y += cardHeight + 12;
    });
  }

  // =========================================================================
  // 5. VERIFIED PASSED SECURITY CONTROLS
  // =========================================================================
  ensureSpace(44);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(
    `3. Verified Passed Security Controls (${report.passedChecks.length})`,
    MARGIN_X,
    y
  );
  y += 14;

  report.passedChecks.forEach((p) => {
    const passTextWidth = CONTENT_WIDTH - 46;
    const titleWrapped = wrapTextExact(
      doc,
      `${p.title} (${p.target})`,
      'helvetica',
      'bold',
      8.5,
      passTextWidth
    );
    const proofWrapped = wrapTextExact(
      doc,
      p.proofSummary.replace(/\s+/g, ' '),
      'courier',
      'normal',
      7.5,
      passTextWidth
    );

    const rowHeight =
      titleWrapped.length * 11 + proofWrapped.length * 10 + 8;
    ensureSpace(rowHeight + 6);

    doc.setFont('courier', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(22, 163, 74);
    doc.text('[PASS]', MARGIN_X, y);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(30, 41, 59);
    doc.text(titleWrapped, MARGIN_X + 44, y);

    const proofY = y + titleWrapped.length * 11;
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(proofWrapped, MARGIN_X + 44, proofY);

    y += rowHeight;
  });

  // =========================================================================
  // 6. PAGE FOOTERS (Strictly Aligned to [MARGIN_X, pageWidth - MARGIN_X])
  // =========================================================================
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    stampSentinelWatermark();
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.5);
    doc.line(
      MARGIN_X,
      pageHeight - 36,
      pageWidth - MARGIN_X,
      pageHeight - 36
    );
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(
      'Sentinel AppSec  |  Engineered by Tanmay Bhardwaj (github.com/tmvoid)',
      MARGIN_X,
      pageHeight - 22
    );
    doc.text(
      `Page ${p} of ${totalPages}`,
      pageWidth - MARGIN_X,
      pageHeight - 22,
      { align: 'right' }
    );
  }

  const slug = (report.projectName || 'audit-report')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

  doc.save(`sentinel-audit-${slug || 'report'}.pdf`);
}
