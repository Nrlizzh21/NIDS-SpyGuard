from flask import Blueprint, jsonify, request, session, redirect, url_for, render_template, send_file
from database import Upload, Prediction
from datetime import datetime, timedelta
from database import db, Prediction, Upload
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
import io

history_bp = Blueprint('history', __name__)

def add_page_number(canvas, doc):
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(A4[0] - inch, 0.75 * inch, text)

@history_bp.route('/history')
def history_page():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('history.html')

@history_bp.route('/api/history')
def history():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    start_date_str = request.args.get('start')
    end_date_str = request.args.get('end')

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None

        if end_date:
            end_date = end_date + timedelta(days=1)
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    query = Upload.query
    if start_date:
        query = query.filter(Upload.upload_time >= start_date)
    if end_date:
        query = query.filter(Upload.upload_time < end_date)

    uploads = query.order_by(Upload.upload_time.desc()).all()

    history_data = []
    for upload in uploads:
        total_records = Prediction.query.filter_by(upload_id=upload.id).count()
        normal_count = Prediction.query.filter_by(upload_id=upload.id, prediction='normal').count()
        dos_count = Prediction.query.filter_by(upload_id=upload.id, prediction='dos').count()
        probe_count = Prediction.query.filter_by(upload_id=upload.id, prediction='probe').count()
        u2r_count = Prediction.query.filter_by(upload_id=upload.id, prediction='u2r').count()
        r2l_count = Prediction.query.filter_by(upload_id=upload.id, prediction='r2l').count()
        unknown_count = Prediction.query.filter_by(upload_id=upload.id, prediction='unknown').count()

        attack_count = dos_count + probe_count + u2r_count + r2l_count + unknown_count

        upload_time = upload.upload_time
        if not upload_time:
            continue

        date_str = upload_time.strftime('%Y/%m/%d')
        time_str = upload_time.strftime('%I:%M:%S %p')

        history_data.append({
            'scan_id': upload.id,
            'timestamp': upload_time.isoformat(),
            'date': date_str,
            'time': time_str,
            'filename': upload.filename,
            'total_records': total_records,
            'attack_count': attack_count,
            'dos_count': dos_count,
            'probe_count': probe_count,
            'u2r_count': u2r_count,
            'r2l_count': r2l_count,
            'normal_count': normal_count,
            'unknown_count': unknown_count
        })

    response_data = {
        'history': history_data,
        'startDate': start_date_str or '',
        'endDate': end_date_str or '',
        'totalResults': len(history_data)
    }

    return jsonify(response_data)

@history_bp.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    import logging
    logging.info(f"Delete scan called with scan_id: {scan_id} (type: {type(scan_id)})")
    logging.info(f"Session contents: {dict(session)}")

    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401


    upload = Upload.query.get(scan_id)
    if not upload:
        return jsonify({'error': 'Scan not found'}), 404

    try:
        Prediction.query.filter_by(upload_id=scan_id).delete()
        db.session.delete(upload)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Scan deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete scan', 'details': str(e)}), 500



@history_bp.route('/history/report')
def history_report():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    start_date_str = request.args.get('start')
    end_date_str = request.args.get('end')

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
        if end_date:
            end_date = end_date + timedelta(days=1)
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    query = Upload.query
    if start_date:
        query = query.filter(Upload.upload_time >= start_date)
    if end_date:
        query = query.filter(Upload.upload_time < end_date)

    uploads = query.order_by(Upload.upload_time.asc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),  
                            rightMargin=inch, leftMargin=inch,
                            topMargin=inch, bottomMargin=inch)
    elements = []
    styles = getSampleStyleSheet()

    styleTitle = styles['Title']
    styleTitle.fontSize = 16
    styleTitle.leading = 20
    styleTitle.alignment = 1

    styleHeader = ParagraphStyle(name='TableHeader', fontSize=9, fontName='Helvetica-Bold',
                                 alignment=1, textColor=colors.whitesmoke)
    styleWrapped = ParagraphStyle('wrapped', parent=styles['Normal'],
                                  wordWrap='CJK', fontSize=8.5, leading=11)

    def safe_text(text, max_len=100):
        return str(text).replace('\n', ' ').replace('\r', '')[:max_len]

    elements.append(Paragraph("AF Smart Sdn. Bhd.", styleTitle))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("SPYGUARD History Report", styleWrapped))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Date Range: {start_date_str or 'All'} to {end_date_str or 'All'}", styleWrapped))
    elements.append(Spacer(1, 24))

    data = [
        [Paragraph('No', styleHeader),
         Paragraph('Date', styleHeader),
         Paragraph('Time', styleHeader),
         Paragraph('File Name', styleHeader),
         Paragraph('Attack Category', styleHeader), '', '', '',
         Paragraph('Normal', styleHeader),
         Paragraph('Unknown', styleHeader),
         Paragraph('Total Attacks', styleHeader),
         Paragraph('Total Records', styleHeader)],

        ['', '', '', '',
         Paragraph('DoS', styleHeader),
         Paragraph('Probe', styleHeader),
         Paragraph('U2R', styleHeader),
         Paragraph('R2L', styleHeader),
         '', '', '', '']
    ]

    for idx, upload in enumerate(uploads, start=1):
        try:
            total_records = Prediction.query.filter_by(upload_id=upload.id).count()
            normal_count = Prediction.query.filter_by(upload_id=upload.id, prediction='normal').count()
            dos_count = Prediction.query.filter_by(upload_id=upload.id, prediction='dos').count()
            probe_count = Prediction.query.filter_by(upload_id=upload.id, prediction='probe').count()
            u2r_count = Prediction.query.filter_by(upload_id=upload.id, prediction='u2r').count()
            r2l_count = Prediction.query.filter_by(upload_id=upload.id, prediction='r2l').count()
            unknown_count = Prediction.query.filter_by(upload_id=upload.id, prediction='unknown').count()
            total_attacks = dos_count + probe_count + u2r_count + r2l_count

            upload_time = upload.upload_time
            if not upload_time:
                continue

            date_str = upload_time.strftime('%Y/%m/%d')
            time_str = upload_time.strftime('%I:%M:%S %p')
            filename = upload.filename or "N/A"
            if len(filename) > 40:
                filename = filename[:40] + "..."

            data.append([
                Paragraph(safe_text(idx), styleWrapped),
                Paragraph(safe_text(date_str), styleWrapped),
                Paragraph(safe_text(time_str), styleWrapped),
                Paragraph(safe_text(filename), styleWrapped),
                Paragraph(safe_text(dos_count), styleWrapped),
                Paragraph(safe_text(probe_count), styleWrapped),
                Paragraph(safe_text(u2r_count), styleWrapped),
                Paragraph(safe_text(r2l_count), styleWrapped),
                Paragraph(safe_text(normal_count), styleWrapped),
                Paragraph(safe_text(unknown_count), styleWrapped),
                Paragraph(safe_text(total_attacks), styleWrapped),
                Paragraph(safe_text(total_records), styleWrapped)
            ])
        except Exception as e:
            print(f"Error processing row for upload {upload.id}: {e}")

    table = Table(data,
                  colWidths=[30, 60, 60, 150, 40, 40, 40, 40, 50, 50, 50, 55],  # ✅ more horizontal space
                  hAlign='CENTER')

    table_style = TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BACKGROUND', (0, 0), (-1, 1), colors.HexColor('#2E4053')),
        ('TEXTCOLOR', (0, 0), (-1, 1), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('SPAN', (0, 0), (0, 1)),  # No
        ('SPAN', (1, 0), (1, 1)),  # Date
        ('SPAN', (2, 0), (2, 1)),  # Time
        ('SPAN', (3, 0), (3, 1)),  # File Name
        ('SPAN', (4, 0), (7, 0)),  # Attack Category
        ('SPAN', (8, 0), (8, 1)),  # Normal
        ('SPAN', (9, 0), (9, 1)),  # Unknown
        ('SPAN', (10, 0), (10, 1)),  # Total Attacks
        ('SPAN', (11, 0), (11, 1)),  # Total Records
    ])

    for i in range(2, len(data)):
        bg_color = colors.HexColor('#F2F4F4') if i % 2 == 0 else colors.white
        table_style.add('BACKGROUND', (0, i), (-1, i), bg_color)

    table.setStyle(table_style)
    elements.append(table)

    elements.append(Spacer(1, 24))
    elements.append(Paragraph(f"Total Scans: {len(uploads)}", styleWrapped))

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="history_report.pdf", mimetype='application/pdf')
