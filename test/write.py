from flask import Blueprint, render_template, redirect, url_for, flash, jsonify
from scanner.config import MongoDbConfig
import json
from datetime import datetime

admin_base = Blueprint('admin', __name__, url_prefix='/admin')

db = MongoDbConfig()

@admin_base.route('/')
@admin_base.route('/dashboard')
def dashboard():

    try:
        stats = {
            'tlds': db.suspicious_tlds.count_documents({'is_active': True}),
            'brands': db.brands.count_documents({'is_active': True}),
            'blacklists': db.blacklisted_domains.count_documents({'is_active': True}),
            'keywords': db.suspicious_keywords.count_documents({'is_active': True})
        }

        tld_risks = {}
        for risks in ['low', 'medium', 'high', 'critical']:
            tld_risks[risks] = db.suspicious_tlds.count_documents({
                'is_active': True,
                'risk_level': risks
            })

        keywords_risks = {}
        for risks in ['low', 'medium', 'high']:
            keywords_risks[risks] = db.suspicious_keywords.count_documents({
                'is_active': True,
                'risk': risks
            })

        recent_tlds = list(db.suspicious_tlds.find({'is_active': True})).sort('added_date', -1).limit(5)

        recent_brands = list(db.suspicious_keywords.find({'is_active': True})).sort('added_date', -1).limit(5)

        return render_template('admin/dashboard.html',
                               stats = stats,
                               tld_risks = tld_risks,
                               keywords_risks = keywords_risks,
                               recent_tlds = recent_tlds,
                               recent_brands = recent_brands)
    
    except Exception as e:
        flash(f"Error Loading Dashboard: {str(e)}", 'error')
        return render_template('admin/dashboard.html', stats = {}, error = str(e))

@admin_base.route('/tlds')
def tlds_list():
    pass

