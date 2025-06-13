# ReconTools/ReportGenerator.py
import base64
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import json # For pretty printing dicts in PDF
import logging

logger = logging.getLogger(__name__)

def generate_pdf_from_summarized_sections(report_title: str, sections_data: list, generation_timestamp: str) -> str:
    """
    Generates a PDF report from pre-summarized sections.
    Args:
        report_title: The main title for the report.
        sections_data: A list of dictionaries, where each dict represents a section.
                       Expected keys per section: "section_title" (str),
                                                  "summary_text" (str, LLM-generated),
                                                  "raw_data_snippet" (dict/list/str, optional, for context).
        generation_timestamp: Timestamp for when the report generation was initiated.
    Returns:
        A base64 encoded string of the generated PDF, or an error message.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(report_title, styles['h1']))
    story.append(Paragraph(f"Report Generated: {generation_timestamp}", styles['Normal']))
    story.append(Spacer(1, 24)) # More space after title block

    logger.info(f"ReportGenerator: Received sections_data with {len(sections_data)} items.")

    def add_data_block_for_snippet(data, title="Supporting Data Snippet", is_json=True):
        # This function is now correctly defined and can be called from the loop below.
        if data:
            story.append(Spacer(1, 4)) # Space before snippet
            story.append(Paragraph(f"<i>{title}:</i>", styles['Italic']))
            story.append(Spacer(1, 2))
            if is_json or isinstance(data, (dict, list)):
                try:
                    # Ensure data is serializable before dumping
                    serializable_data = json.loads(json.dumps(data, default=str))
                    data_str = json.dumps(serializable_data, indent=2, sort_keys=True)
                    for line in data_str.splitlines()[:20]: # Limit snippet lines
                         # Replace leading spaces with non-breaking spaces for pre-like formatting
                         leading_spaces = len(line) - len(line.lstrip(' '))
                         formatted_line = " " * leading_spaces + line.lstrip(' ') # Use   for ReportLab
                         story.append(Paragraph(formatted_line, styles['Code']))
                    if len(data_str.splitlines()) > 20:
                        story.append(Paragraph("<i>... (snippet truncated)</i>", styles['Italic']))
                except Exception as e:
                    logger.warning(f"Could not JSON dump data for PDF snippet '{title}': {e}")
                    story.append(Paragraph(str(data)[:500] + ("..." if len(str(data)) > 500 else ""), styles['Normal']))
            else: # Plain string data
                story.append(Paragraph(str(data)[:500] + ("..." if len(str(data)) > 500 else ""), styles['Normal']))
        story.append(Spacer(1, 6)) # Space after snippet

    # Main loop to process sections - CORRECTED INDENTATION
    for section_idx, section in enumerate(sections_data):
        logger.debug(f"ReportGenerator: Processing section {section_idx + 1}/{len(sections_data)}: {section.get('section_title') if isinstance(section, dict) else 'Malformed section'}")
        
        if not isinstance(section, dict):
            logger.warning(f"ReportGenerator: Section {section_idx + 1} is not a dictionary, skipping. Data: {section}")
            story.append(Paragraph(f"Error: Section {section_idx + 1} data is malformed. Expected a dictionary.", styles['Normal']))
            story.append(Spacer(1,12))
            continue

        # The LLM currently sends 'title', so we prefer 'section_title' but fallback to 'title'
        section_title_text = section.get("section_title", section.get("title", f"Untitled Section {section_idx + 1}"))
        
        # The LLM currently sends 'summary' (which is just the title again).
        # We prefer 'summary_text', fallback to 'summary', then to a default message.
        summary_text = section.get("summary_text")
        if summary_text is None:
            summary_text = section.get("summary", f"No summary provided for section: {section_title_text}")
        
        raw_data_snippet = section.get("raw_data_snippet")

        story.append(Paragraph(section_title_text, styles['h2']))
        story.append(Spacer(1, 6))
        
        if isinstance(summary_text, str):
            for paragraph_text in summary_text.split('\n'):
                story.append(Paragraph(paragraph_text, styles['Normal']))
        else: 
            story.append(Paragraph(str(summary_text), styles['Normal'])) # Fallback for non-string summary

        # Call add_data_block_for_snippet if raw_data_snippet exists
        if raw_data_snippet:
            add_data_block_for_snippet(raw_data_snippet, title="Supporting Data Snippet")
        else: # Add a small spacer even if no snippet, to separate from next section title
            story.append(Spacer(1, 6)) 
        
        story.append(Spacer(1, 12)) # Space before the next section

    try:
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return base64.b64encode(pdf_bytes).decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating PDF from summarized sections for '{report_title}': {e}", exc_info=True)
        error_message = f"Critical Error during PDF generation: {str(e)}"
        error_buffer = BytesIO()
        error_doc = SimpleDocTemplate(error_buffer, pagesize=letter)
        error_story = [Paragraph("PDF Generation Failed", styles['h1']), Paragraph(error_message, styles['Normal'])]
        try:
            error_doc.build(error_story)
            error_pdf_bytes = error_buffer.getvalue()
            error_buffer.close()
            return base64.b64encode(error_pdf_bytes).decode('utf-8')
        except Exception:
            return base64.b64encode(error_message.encode('utf-8')).decode('utf-8')

# The generate_pdf_from_db_data function remains unchanged as it was not implicated.
def generate_pdf_from_db_data(report_data: dict) -> str:
    """
    Generates a PDF report from aggregated data retrieved from the database.
    Args:
        report_data: A dictionary containing the structured data for the report.
                     Expected keys: 'target_domain', 'retrieval_timestamp',
                                    'dns_info', 'subdomains', 'port_scans', 'web_app_analyses'.
    Returns:
        A base64 encoded string of the generated PDF, or an error message if PDF generation fails.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"Vulnerability Report: {report_data.get('target_domain', 'N/A')}", styles['h1']))
    story.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
    story.append(Paragraph(f"Data Sourced From DB On: {report_data.get('retrieval_timestamp', 'N/A')}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Helper to add sections
    def add_section_title(title_text):
        story.append(Spacer(1, 12))
        story.append(Paragraph(title_text, styles['h2']))
        story.append(Spacer(1, 6))

    def add_subsection_title(title_text):
        story.append(Spacer(1, 6))
        story.append(Paragraph(title_text, styles['h3']))
        story.append(Spacer(1, 4))

    def add_data_block(data, title="Data", is_json=False):
        if data:
            story.append(Paragraph(f"<b>{title}:</b>", styles['Normal']))
            if is_json or isinstance(data, (dict, list)):
                try:
                    data_str = json.dumps(data, indent=2, sort_keys=True)
                    # ReportLab Paragraphs don't handle newlines well directly from json.dumps
                    # Use Preformatted style or split lines.
                    # For simplicity, using multiple paragraphs for each line.
                    for line in data_str.splitlines():
                         # Replace spaces with non-breaking spaces for pre-like formatting
                         story.append(Paragraph(line.replace(" ", " "), styles['Code']))
                except Exception as e:
                    logger.warning(f"Could not JSON dump data for PDF section '{title}': {e}")
                    story.append(Paragraph(str(data)[:1000] + ("..." if len(str(data)) > 1000 else ""), styles['Normal']))
            else:
                story.append(Paragraph(str(data), styles['Normal']))
        else:
            story.append(Paragraph(f"<i>No {title.lower()} data found in the database for this target.</i>", styles['Italic']))
        story.append(Spacer(1, 6))

    # --- Target Information ---
    add_section_title("Target Information")
    story.append(Paragraph(f"<b>Domain:</b> {report_data.get('target_domain', 'N/A')}", styles['Normal']))
    story.append(Spacer(1, 6))

    # --- DNS Information ---
    dns_info_data = report_data.get('dns_info')
    if dns_info_data:
        add_section_title("DNS Enumeration Results")
        # DnsEnumResult has 'records' (DnsRecordCollection) and 'errors'
        dns_records_collection = dns_info_data.get('records', {})
        
        actual_dns_records = dns_records_collection.get('dns_records', {})
        if actual_dns_records:
            add_subsection_title("DNS Records")
            for record_type, records in actual_dns_records.items():
                if record_type.startswith("CNAME_"): # Handle CNAME resolved data
                    add_data_block(records, title=f"Resolved Records for {record_type.split('_', 1)[1]}", is_json=True)
                else:
                    add_data_block(records, title=f"{record_type} Records", is_json=True)
        else:
            story.append(Paragraph("<i>No specific DNS records found.</i>", styles['Italic']))

        zt_results = dns_records_collection.get('zone_transfer_results', [])
        if zt_results:
            add_subsection_title("Zone Transfer Attempts")
            for i, zt_attempt in enumerate(zt_results): # zt_results is a list of dicts
                # zt_attempt itself is the data from a single NS server if successful
                add_data_block(zt_attempt, title=f"Zone Transfer Result {i+1}", is_json=True)
        
        spf_dmarc = dns_records_collection.get('spf_dmarc_analysis', {})
        if spf_dmarc:
            add_subsection_title("SPF/DMARC Analysis")
            add_data_block(spf_dmarc, is_json=True)
        
        dns_errors = dns_info_data.get('errors', [])
        if dns_errors:
            add_data_block(dns_errors, title="DNS Enumeration Errors", is_json=True)

    # --- Subdomain Information ---
    subdomain_data = report_data.get('subdomains')
    if subdomain_data:
        add_section_title("Subdomain Enumeration Results")
        story.append(Paragraph(f"<b>Total Subdomains Found:</b> {subdomain_data.get('count', 0)}", styles['Normal']))
        if subdomain_data.get('subdomains'):
            subs_list = subdomain_data.get('subdomains', [])
            for sub_item in subs_list[:30]: # Display first 30
                story.append(Paragraph(f"- {sub_item}", styles['Normal']))
            if len(subs_list) > 30:
                story.append(Paragraph(f"<i>... and {len(subs_list) - 30} more subdomains (list truncated).</i>", styles['Italic']))
        else:
            story.append(Paragraph("<i>No subdomains listed.</i>", styles['Italic']))
        
        sub_errors = subdomain_data.get('errors', []) # Assuming 'errors' key might exist
        if sub_errors:
            add_data_block(sub_errors, title="Subdomain Enumeration Errors", is_json=True)


    # --- Port Scan Information ---
    port_scans_data = report_data.get('port_scans', [])
    if port_scans_data:
        add_section_title("Port Scan Results")
        for ps_result in port_scans_data:
            scan_target_display = ps_result.get('target', 'N/A')
            if ps_result.get('ip_address') and ps_result.get('ip_address') != ps_result.get('target'):
                scan_target_display += f" (IP: {ps_result.get('ip_address')})"
            add_subsection_title(f"Scan for: {scan_target_display}")
            
            if ps_result.get('aggregated_os_fingerprint'):
                add_data_block(ps_result['aggregated_os_fingerprint'], title="Aggregated OS Fingerprint", is_json=True)

            open_ports_table_data = []
            for port_info in ps_result.get('port_details', []):
                if port_info.get('state', '').lower() == 'open': # Ensure we only show open
                    open_ports_table_data.append([
                        str(port_info.get('port', '')),
                        port_info.get('protocol', ''),
                        port_info.get('service_name', ''),
                        port_info.get('version', ''),
                        (port_info.get('banner', '')[:45] + '...') if len(port_info.get('banner', '')) > 45 else port_info.get('banner', '')
                    ])
            
            if open_ports_table_data:
                story.append(Paragraph("<b>Open Ports:</b>", styles['Normal']))
                table_data = [["Port", "Proto", "Service", "Version", "Banner Snippet"]] + open_ports_table_data
                col_widths = [40, 40, 100, 100, 140]
                try:
                    t = Table(table_data, colWidths=col_widths)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ]))
                    story.append(t)
                except Exception as table_err:
                    logger.error(f"Error creating port table for PDF: {table_err}")
                    story.append(Paragraph(f"<i>Error displaying port table: {table_err}</i>", styles['Italic']))
                    add_data_block(open_ports_table_data, title="Open Ports (Raw Data)", is_json=True)

            else:
                story.append(Paragraph("<i>No open ports found or reported for this target.</i>", styles['Italic']))
            
            ps_errors = ps_result.get('errors', [])
            if ps_errors:
                add_data_block(ps_errors, title="Port Scan Errors", is_json=True)
            story.append(Spacer(1, 6))

    # --- Web Application Analysis ---
    web_app_analyses_data = report_data.get('web_app_analyses', [])
    if web_app_analyses_data:
        add_section_title("Web Application Analysis Results")
        for web_analysis in web_app_analyses_data:
            # SiteMapAndAnalyze results have a 'summary' and 'scanned_pages_details', 'active_scan_vulnerabilities_found'
            summary = web_analysis.get('summary', {})
            web_target_url = summary.get('target_url', 'N/A')
            add_subsection_title(f"Analysis for: {web_target_url}")

            story.append(Paragraph(f"<b>Status:</b> {summary.get('status_message', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"<b>Pages Processed:</b> {summary.get('total_pages_processed_with_details', 0)}", styles['Normal']))
            
            detected_tech = summary.get('detected_domain_technologies', [])
            if detected_tech:
                add_data_block(detected_tech, title="Detected Technologies (Domain-wide)", is_json=True)

            # Consolidate vulnerabilities from scanned_pages_details (passive) and active_scan_vulnerabilities_found (active)
            all_vulnerabilities_for_site = []
            # Passive findings from page details
            for page_detail in web_analysis.get('scanned_pages_details', []):
                page_url_vuln = page_detail.get('url', 'Unknown Page')
                for finding in page_detail.get('passive_findings_and_hints', []):
                    all_vulnerabilities_for_site.append({
                        "scan_type": "Passive",
                        "page_url": page_url_vuln,
                        "name": finding.get('name', finding.get('passive_hint_type', 'N/A')),
                        "severity": finding.get('severity', 'N/A'),
                        "evidence": finding.get('evidence', 'N/A')[:150] # Truncate
                    })
            # Active findings (already collected at the top level of SiteMapAndAnalyze result)
            for alert in web_analysis.get('active_scan_vulnerabilities_found', []):
                 all_vulnerabilities_for_site.append({
                        "scan_type": "Active",
                        "page_url": alert.get('url_tested', alert.get('url', 'N/A')),
                        "name": alert.get('name', alert.get('type', 'N/A')),
                        "severity": alert.get('severity', 'N/A'),
                        "evidence": alert.get('evidence', alert.get('description', 'N/A'))[:150] # Truncate
                    })

            if all_vulnerabilities_for_site:
                story.append(Paragraph("<b>Identified Vulnerabilities/Hints:</b>", styles['Normal']))
                vuln_table_data = [["Scan Type", "Page URL", "Name", "Severity", "Evidence Snippet"]]
                for vuln in all_vulnerabilities_for_site:
                    vuln_table_data.append([
                        vuln['scan_type'],
                        (vuln['page_url'][:40] + '...') if len(vuln['page_url']) > 40 else vuln['page_url'],
                        (vuln['name'][:35] + '...') if len(vuln['name']) > 35 else vuln['name'],
                        vuln['severity'],
                        vuln['evidence']
                    ])
                
                col_widths_vuln = [60, 100, 100, 60, 120]
                try:
                    vt = Table(vuln_table_data, colWidths=col_widths_vuln)
                    vt.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkred if any(v['scan_type']=='Active' for v in all_vulnerabilities_for_site) else colors.darkorange),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgoldenrodyellow),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ]))
                    story.append(vt)
                except Exception as table_err_vuln:
                    logger.error(f"Error creating vulnerability table for PDF: {table_err_vuln}")
                    story.append(Paragraph(f"<i>Error displaying vulnerability table: {table_err_vuln}</i>", styles['Italic']))
                    add_data_block(all_vulnerabilities_for_site, title="Vulnerabilities (Raw Data)", is_json=True)
            else:
                story.append(Paragraph("<i>No specific vulnerabilities or significant passive hints reported for this web application.</i>", styles['Italic']))
            
            web_errors = web_analysis.get('summary', {}).get('errors', []) # Assuming errors might be in summary
            if web_errors:
                 add_data_block(web_errors, title="Web Analysis Errors", is_json=True)
            story.append(Spacer(1, 6))

    # --- Build PDF ---
    try:
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return base64.b64encode(pdf_bytes).decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating PDF for {report_data.get('target_domain', 'N/A')}: {e}", exc_info=True)
        # Fallback: return a base64 encoded error message or a very simple PDF indicating error
        error_message = f"Critical Error during PDF generation: {str(e)}"
        # Create a minimal PDF with the error
        error_buffer = BytesIO()
        error_doc = SimpleDocTemplate(error_buffer, pagesize=letter)
        error_story = [Paragraph("PDF Generation Failed", styles['h1']), Paragraph(error_message, styles['Normal'])]
        try:
            error_doc.build(error_story)
            error_pdf_bytes = error_buffer.getvalue()
            error_buffer.close()
            return base64.b64encode(error_pdf_bytes).decode('utf-8')
        except Exception: # If even error PDF fails
            return base64.b64encode(error_message.encode('utf-8')).decode('utf-8')