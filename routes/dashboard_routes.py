from flask import Blueprint, jsonify, request, session, redirect, url_for, render_template
from database import Upload
from datetime import datetime, timedelta
from database import db, Prediction, Upload


dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard_data')
def api_dashboard_data():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Initialize query for uploads
    query = Upload.query
    
    # Get date parameters from request
    start_date_str = request.args.get('start')
    end_date_str = request.args.get('end')
    
    # Set default date range
    if not start_date_str or not end_date_str:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        start_date_str = start_date.strftime('%Y-%m-%d')
        end_date_str = end_date.strftime('%Y-%m-%d')
    else:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            end_date = end_date + timedelta(days=1)
            query = query.filter(Upload.upload_time >= start_date, Upload.upload_time <= end_date)
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    
    # Query all uploads or filtered uploads
    recent_uploads = query.all()
    
    # Aggregate counts
    dos_count = probe_count = u2r_count = r2l_count = normal_count = unknown_count = total_predictions = 0
    
    for upload in recent_uploads:
        upload_id = upload.id
        total_predictions += Prediction.query.filter_by(upload_id=upload_id).count()
        dos_count += Prediction.query.filter_by(upload_id=upload_id, prediction='dos').count()
        probe_count += Prediction.query.filter_by(upload_id=upload_id, prediction='probe').count()
        u2r_count += Prediction.query.filter_by(upload_id=upload_id, prediction='u2r').count()
        r2l_count += Prediction.query.filter_by(upload_id=upload_id, prediction='r2l').count()
        normal_count += Prediction.query.filter_by(upload_id=upload_id, prediction='normal').count()
        unknown_count += Prediction.query.filter_by(upload_id=upload_id, prediction='unknown').count()
    
    attack_count = dos_count + probe_count + u2r_count + r2l_count + unknown_count
    
    # Calculate the date range span in days
    date_span = (end_date - start_date).days

    # Determine appropriate grouping based on date span
    if date_span > 90:  # More than 3 months, group by month
        time_series_data = generate_time_series(start_date, end_date, recent_uploads, 'month')
    elif date_span > 30:  # More than 30 days, group by week
        time_series_data = generate_time_series(start_date, end_date, recent_uploads, 'week')
    else:  # Less than or equal to 30 days, group by day
        time_series_data = generate_time_series(start_date, end_date, recent_uploads, 'day')
    
    data = {
        'dosCount': dos_count,
        'probeCount': probe_count,
        'u2rCount': u2r_count,
        'r2lCount': r2l_count,
        'normalCount': normal_count,
        'unknownCount': unknown_count,
        'totalCount': total_predictions,
        'attackCount': attack_count,
        'timeSeriesData': time_series_data,
        'lastUpdated': datetime.utcnow().isoformat() + 'Z'
    }
    
    return jsonify(data)


def generate_time_series(start_date, end_date, uploads, group_by):
    time_series_data = []
    
    if group_by == 'day':
        current_date = start_date
        while current_date < end_date:
            next_date = current_date + timedelta(days=1)
            day_uploads = [u for u in uploads if current_date <= u.upload_time < next_date]
            time_series_data.append(generate_counts(day_uploads, current_date))
            current_date = next_date
            
    elif group_by == 'week':
        start_weekday = start_date.weekday()
        adjusted_start = start_date - timedelta(days=start_weekday)
        current_date = adjusted_start
        while current_date < end_date:
            week_end = current_date + timedelta(days=7)
            week_uploads = [u for u in uploads if current_date <= u.upload_time < week_end]
            time_series_data.append(generate_counts(week_uploads, current_date))
            current_date = week_end
    
    elif group_by == 'month':
        adjusted_start = start_date.replace(day=1)
        current_date = adjusted_start
        while current_date < end_date:
            if current_date.month == 12:
                month_end = current_date.replace(year=current_date.year + 1, month=1)
            else:
                month_end = current_date.replace(month=current_date.month + 1)
            month_uploads = [u for u in uploads if current_date <= u.upload_time < month_end]
            time_series_data.append(generate_counts(month_uploads, current_date))
            current_date = month_end
    
    return time_series_data


def generate_counts(uploads, current_date):
    normal = dos = probe = u2r = r2l = 0
    for upload in uploads:
        normal += Prediction.query.filter_by(upload_id=upload.id, prediction='normal').count()
        dos += Prediction.query.filter_by(upload_id=upload.id, prediction='dos').count()
        probe += Prediction.query.filter_by(upload_id=upload.id, prediction='probe').count()
        u2r += Prediction.query.filter_by(upload_id=upload.id, prediction='u2r').count()
        r2l += Prediction.query.filter_by(upload_id=upload.id, prediction='r2l').count()

    return {
        'date': current_date.strftime('%Y-%m-%d'),
        'normal': normal,
        'dos': dos,
        'probe': probe,
        'u2r': u2r,
        'r2l': r2l
    }
