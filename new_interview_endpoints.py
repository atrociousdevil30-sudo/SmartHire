# Add these endpoints to app.py after the employee_ready_for_interview endpoint

@app.route('/api/hr/interview/start/<int:session_id>', methods=['POST'])
@login_required('hr')
def hr_start_interview(session_id):
    """HR starts interview for ready employee"""
    try:
        session_record = InterviewSession.query.get_or_404(session_id)
        session_record.status = 'in_progress'
        session_record.hr_id = session.get('user_id')
        session_record.started_at = datetime.utcnow()
        db.session.commit()
        
        employee = session_record.employee
        notification = Message(
            subject='Interview Started - Join Now',
            content='Your interview has started. Click the Join button to begin.',
            sender_id=session.get('user_id'),
            recipient_id=employee.id,
            message_type='interview_join',
            priority='high'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Interview started', 'session_id': session_record.id})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error starting interview: {str(e)}')
        return jsonify({'status': 'error', 'message': 'Failed to start interview'}), 500

@app.route('/api/hr/ready-employees', methods=['GET'])
@login_required('hr')
def get_ready_employees():
    """Get list of employees ready for interview"""
    try:
        ready_sessions = InterviewSession.query.filter_by(status='ready').order_by(InterviewSession.created_at.desc()).all()
        employees = []
        for sess in ready_sessions:
            employees.append({
                'session_id': sess.id,
                'employee_id': sess.employee_id,
                'employee_name': sess.employee.full_name,
                'email': sess.employee.email,
                'department': sess.employee.department,
                'ready_since': sess.created_at.isoformat()
            })
        return jsonify({'status': 'success', 'employees': employees})
    except Exception as e:
        app.logger.error(f'Error fetching ready employees: {str(e)}')
        return jsonify({'status': 'error', 'message': 'Failed to fetch ready employees'}), 500
