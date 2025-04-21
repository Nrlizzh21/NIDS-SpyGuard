from flask import Blueprint, render_template
from routes.auth_routes import login_required

about_bp = Blueprint('about', __name__)

@about_bp.route('/about')
@login_required
def about():
    return render_template('about.html')
