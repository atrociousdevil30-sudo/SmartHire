from flask import Blueprint, render_template
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import random
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def dashboard():
    # Sample data - replace with actual data from your database
    resume_scores = [random.randint(60, 100) for _ in range(50)]
    sentiment_data = {
        'Positive': random.randint(5, 15),
        'Neutral': random.randint(2, 10),
        'Negative': random.randint(1, 5)
    }
    
    # Generate hiring trends data
    end_date = datetime.now()
    start_date = end_date - timedelta(days=90)
    date_range = pd.date_range(start_date, end_date, freq='W')
    trends_data = {
        'date': date_range,
        'applications': [random.randint(10, 50) for _ in date_range],
        'interviews': [random.randint(5, 25) for _ in date_range],
        'hires': [random.randint(1, 10) for _ in date_range]
    }
    
    # Generate top candidates data
    candidates = [
        {'name': 'John Doe', 'score': 92, 'status': 'Interview Scheduled', 'applied': (end_date - timedelta(days=5)).strftime('%Y-%m-%d')},
        {'name': 'Jane Smith', 'score': 88, 'status': 'Offer Sent', 'applied': (end_date - timedelta(days=10)).strftime('%Y-%m-%d')},
        {'name': 'Robert Johnson', 'score': 85, 'status': 'New Application', 'applied': (end_date - timedelta(days=1)).strftime('%Y-%m-%d')},
        {'name': 'Emily Davis', 'score': 82, 'status': 'Interviewed', 'applied': (end_date - timedelta(days=7)).strftime('%Y-%m-%d')},
        {'name': 'Michael Brown', 'score': 79, 'status': 'Screening', 'applied': (end_date - timedelta(days=3)).strftime('%Y-%m-%d')},
    ]
    
    # Create charts
    resume_distribution = create_resume_score_chart(resume_scores)
    sentiment_chart = create_sentiment_chart(sentiment_data)
    hiring_trends = create_hiring_trends_chart(trends_data)
    
    return render_template('dashboard.html',
                         resume_distribution=resume_distribution,
                         sentiment_chart=sentiment_chart,
                         hiring_trends=hiring_trends,
                         candidates=candidates,
                         sentiment_data=sentiment_data)

def create_resume_score_chart(scores):
    fig = px.histogram(
        x=scores, 
        nbins=10,
        labels={'x': 'Score', 'y': 'Count'},
        title='Resume Score Distribution',
        color_discrete_sequence=['#7b2cbf'],
        template='plotly_dark',
        opacity=0.8
    )
    
    fig.update_layout(
        showlegend=False,
        paper_bgcolor='#1a1a1a',
        plot_bgcolor='#2d2d2d',
        font=dict(color='#f8f9fa'),
        xaxis=dict(
            gridcolor='#444',
            linecolor='#444',
            zerolinecolor='#444'
        ),
        yaxis=dict(
            gridcolor='#444',
            linecolor='#444',
            zerolinecolor='#444'
        )
    )
    
    return fig.to_html(full_html=False, config={'displayModeBar': False})

def create_sentiment_chart(sentiment_data):
    fig = px.pie(
        names=list(sentiment_data.keys()),
        values=list(sentiment_data.values()),
        title='Exit Interview Sentiment Analysis',
        color=list(sentiment_data.keys()),
        color_discrete_map={
            'Positive': '#34A853',
            'Neutral': '#FBBC05',
            'Negative': '#EA4335'
        },
        template='plotly_dark'
    )
    
    fig.update_layout(
        paper_bgcolor='#1a1a1a',
        font=dict(color='#f8f9fa'),
        legend=dict(
            bgcolor='#2d2d2d',
            bordercolor='#444',
            borderwidth=1
        )
    )
    
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        marker=dict(line=dict(color='#2d2d2d', width=2)),
        opacity=0.9
    )
    
    return fig.to_html(full_html=False, config={'displayModeBar': False})

def create_hiring_trends_chart(trends_data):
    fig = go.Figure()
    
    # Add traces with custom colors to match the theme
    fig.add_trace(go.Scatter(
        x=trends_data['date'],
        y=trends_data['applications'],
        name='Applications',
        line=dict(color='#7b2cbf', width=3),
        mode='lines+markers',
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=trends_data['date'],
        y=trends_data['interviews'],
        name='Interviews',
        line=dict(color='#FBBC05', width=3),
        mode='lines+markers',
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=trends_data['date'],
        y=trends_data['hires'],
        name='Hires',
        line=dict(color='#34A853', width=3),
        mode='lines+markers',
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title='Hiring Trends (Last 90 Days)',
        xaxis_title='Date',
        yaxis_title='Count',
        legend=dict(
            orientation='h',
            yanchor='bottom',
            y=1.02,
            xanchor='right',
            x=1,
            bgcolor='#2d2d2d',
            bordercolor='#444',
            borderwidth=1
        ),
        paper_bgcolor='#1a1a1a',
        plot_bgcolor='#2d2d2d',
        font=dict(color='#f8f9fa'),
        xaxis=dict(
            gridcolor='#444',
            linecolor='#444',
            zerolinecolor='#444',
            showgrid=True
        ),
        yaxis=dict(
            gridcolor='#444',
            linecolor='#444',
            zerolinecolor='#444',
            showgrid=True
        ),
        hovermode='x unified',
        hoverlabel=dict(
            bgcolor='#2d2d2d',
            font_size=12,
            font_family='Arial'
        )
    )
    
    return fig.to_html(full_html=False, config={'displayModeBar': False})