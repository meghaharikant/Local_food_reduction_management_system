from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import db, FoodItem


donor_bp = Blueprint('donor', __name__)

@donor_bp.route('/donate', methods=['GET', 'POST'])
@login_required
def donate_food():
    if current_user.role != 'donor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        new_food = FoodItem(name=name, quantity=quantity, donor_id=current_user.id)
        db.session.add(new_food)
        db.session.commit()
        flash('Food donation posted successfully!', 'success')
        return redirect(url_for('donor.view_donations'))
    return render_template('donate_food.html')

@donor_bp.route('/donations')
@login_required
def view_donations():
    if current_user.role != 'donor':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))
    donations = FoodItem.query.filter_by(donor_id=current_user.id).all()
    return render_template('view_donations.html', donations=donations)
