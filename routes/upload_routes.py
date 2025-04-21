from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from database import db, Upload, Prediction
import joblib
import pandas as pd
import numpy as np
import pytz
from datetime import datetime

upload_bp = Blueprint('upload', __name__)

# Load model, scaler, and encoders
model = joblib.load('models/rf_model.pkl')
scaler = joblib.load('models/scaler.pkl')
encoders = joblib.load('models/label_encoders.pkl')

# Define categorical columns and feature columns
categorical_columns = ['protocol_type', 'service', 'flag']
feature_columns = [
    "duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    import time
    start_time = time.time()

    print(f"Session contents at upload: {dict(session)}")
    user_id = session.get('user_id')
    print(f"user_id from session: {user_id}")

    if 'username' not in session:
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('upload.html')

    try:
        # POST method: handle file upload and prediction
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'Only CSV files are allowed'}), 400

        # Check file size (limit to 10 MB )
        file.seek(0, 2)  
        file_length = file.tell()
        file.seek(0) 
        max_size = 10 * 1024 * 1024  # 10 MB in bytes
        if file_length > max_size:
            return jsonify({'error': 'File size exceeds 10 MB limit'}), 400

        import io
        file_content = file.read().decode('utf-8')
        print("Uploaded file content preview:")
        print(file_content[:500])  # print first 500 characters for debugging
        df = pd.read_csv(io.StringIO(file_content), comment='#')
        
        df_original = df.copy()

        # Add avg_connection_duration_per_service column before encoding and subsetting
        df['avg_connection_duration_per_service'] = 0.0

        # Encode categorical features
        for col in categorical_columns:
            le = encoders.get(col)
            if le:
                try:
                    df.loc[:, col] = le.transform(df[col])
                except ValueError as e:
                    return jsonify({'error': f'Invalid category in column {col}: {str(e)}'}), 400

        # Add avg_connection_duration_per_service to feature_columns list
        if 'avg_connection_duration_per_service' not in feature_columns:
            feature_columns.append('avg_connection_duration_per_service')

        # Check if required columns are present
        missing_cols = set(feature_columns) - set(df.columns)
        if missing_cols:
            return jsonify({'error': f'Missing columns in uploaded CSV: {missing_cols}'}), 400

        # Keep only required columns in correct order
        df = df[feature_columns]

        # Separate numerical and categorical columns
        numerical_columns = [col for col in feature_columns if col not in categorical_columns]

        # Scale only numerical columns
        try:
            df.loc[:, numerical_columns] = df[numerical_columns].astype(float)
            df.loc[:, numerical_columns] = scaler.transform(df[numerical_columns])
        except Exception as e:
            return jsonify({'error': f'Error during feature scaling: {str(e)}'}), 400

        # Predict
        try:
            preds = model.predict(df)
            pred_proba = model.predict_proba(df)
        except Exception as e:
            return jsonify({'error': f'Error during prediction: {str(e)}'}), 500

        # Save predictions to database
        user_id = session.get('user_id')

        # Get current time in Malaysian timezone
        malaysian_tz = pytz.timezone('Asia/Kuala_Lumpur')
        now_utc = datetime.now(pytz.utc)
        now_malaysian = now_utc.astimezone(malaysian_tz)

        # Save upload record to database with timezone-aware timestamp
        upload_record = Upload(
            user_id=user_id,
            filename=file.filename,
            upload_time=now_malaysian  
        )
        db.session.add(upload_record)
        db.session.commit()

        # Save predictions to database linked to upload
        # Count attack classes for this upload
        attack_counts = {
            'dos': 0,
            'normal': 0,
            'probe': 0,
            'r2l': 0,
            'u2r': 0,
            'unknown': 0
        }
        for i, (pred, proba) in enumerate(zip(preds, pred_proba)):
            row_data = df.iloc[i]
            prediction_record = Prediction(
                user_id=user_id,
                upload_id=upload_record.id,
                row_number=i,
                duration=row_data['duration'],
                protocol_type=row_data['protocol_type'],
                service=row_data['service'],
                src_bytes=row_data['src_bytes'],
                dst_bytes=row_data['dst_bytes'],
                prediction=pred,
                confidence=float(np.max(proba))
            )
            db.session.add(prediction_record)
            # Update attack counts
            pred_lower = pred.lower()
            if pred_lower in attack_counts:
                attack_counts[pred_lower] += 1
        db.session.commit()

        # Update upload record with attack counts
        upload_record.dos_count = attack_counts['dos']
        upload_record.normal_count = attack_counts['normal']
        upload_record.probe_count = attack_counts['probe']
        upload_record.r2l_count = attack_counts['r2l']
        upload_record.u2r_count = attack_counts['u2r']
        upload_record.unknown_count = attack_counts['unknown']
        upload_record.total_predictions = len(preds)  
        db.session.commit()

        # Prepare results for rendering
        results = []
        unknown_count = 0

        # For inverse transforming categorical columns
        try:
            inv_protocol = encoders['protocol_type'].inverse_transform(df['protocol_type'].to_numpy(dtype='int')) if 'protocol_type' in df.columns else []
            inv_service = encoders['service'].inverse_transform(df['service'].to_numpy(dtype='int')) if 'service' in df.columns else []
            inv_flag = encoders['flag'].inverse_transform(df['flag'].to_numpy(dtype='int')) if 'flag' in df.columns else []
        except Exception as e:
            return jsonify({'error': f'Error during inverse transformation of categorical columns: {str(e)}'}), 500

        for i in range(len(preds)):
            pred_lower = preds[i].lower()
            if pred_lower not in attack_counts:
                unknown_count += 1
            results.append({
                'row': i + 1,
                'duration': df_original.iloc[i]['duration'],
                'protocol_type': inv_protocol[i] if len(inv_protocol) > i else '',
                'service': inv_service[i] if len(inv_service) > i else '',
                'flag': inv_flag[i] if len(inv_flag) > i else '',
                'src_bytes': df_original.iloc[i]['src_bytes'],
                'dst_bytes': df_original.iloc[i]['dst_bytes'],
                'prediction': preds[i],
                'confidence': np.max(pred_proba[i]),
            })

        total_predictions = len(preds)
        attack_counts['unknown'] = unknown_count

        attack_counts_capitalized = {
            'Normal': attack_counts.get('normal', 0),
            'Probe': attack_counts.get('probe', 0),
            'DOS': attack_counts.get('dos', 0),
            'U2R': attack_counts.get('u2r', 0),
            'R2L': attack_counts.get('r2l', 0),
            'Unknown': attack_counts.get('unknown', 0)
        }

        # Return JSON response for AJAX
        def convert_to_builtin_type(obj):
            if isinstance(obj, (np.integer,)):
                return int(obj)
            elif isinstance(obj, (np.floating,)):
                return float(obj)
            elif isinstance(obj, (np.ndarray,)):
                return obj.tolist()
            else:
                return obj

        import time
        end_time = time.time()
        processing_time = round(end_time - start_time, 2)

        import json
        json_data = json.dumps({
            'success': True,
            'total_predictions': total_predictions,
            'attack_counts': attack_counts_capitalized,
            'processing_time': processing_time,  
            'predictions': results,
            'upload_id': upload_record.id,
            'refresh_dashboard': True  
        }, default=convert_to_builtin_type)

        from flask import Response
        return Response(json_data, mimetype='application/json')
    except Exception as e:
        import traceback
        traceback_str = traceback.format_exc()
        print(f"Exception in upload_page: {traceback_str}")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

@upload_bp.route('/download/<int:upload_id>', methods=['GET'])
def download_predictions(upload_id):
    from io import StringIO
    import csv
    from flask import Response

    upload = Upload.query.get(upload_id)
    if not upload:
        return "Upload not found", 404

    predictions = Prediction.query.filter_by(upload_id=upload_id).all()
    if not predictions:
        return "No predictions found for this upload", 404

    # Create CSV in memory
    si = StringIO()
    cw = csv.writer(si)

    # Write header
    header = [
        'Row Number', 'Duration', 'Protocol Type', 'Service', 'Flag',
        'Source Bytes', 'Destination Bytes', 'Prediction', 'Confidence'
    ]
    cw.writerow(header)

    # Write data rows
    for pred in predictions:
        cw.writerow([
            pred.row_number + 1,  
            pred.duration,
            pred.protocol_type,
            pred.service,
            getattr(pred, 'flag', ''),
            pred.src_bytes,
            pred.dst_bytes,
            pred.prediction,
            pred.confidence
        ])

    output = si.getvalue()
    si.close()

    # Prepare response
    response = Response(
        output,
        mimetype='text/csv',
        headers={
            "Content-Disposition": f"attachment;filename=predictions_{upload_id}.csv"
        }
    )
    return response

