from flask import Blueprint, render_template
from routes.auth_routes import login_required

faqs_bp = Blueprint('faqs', __name__)

@faqs_bp.route('/faqs')
@login_required
def faqs():
    return render_template('faqs.html')
