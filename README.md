# Echo

Echo is a cybersecurity and digital privacy awareness platform that helps users understand their online visibility through an interactive risk assessment dashboard.

The project simulates how different audiences—including recruiters, advertisers, and threat actors—might view a user's public online footprint and provides personalized recommendations to improve privacy and reduce exposure.

---

## Overview

Echo analyzes a username or online identity and generates a visibility report containing:

* Visibility Score (0–100)
* Public Signals Analysis
* Exposure Risk Assessment
* Privacy Recommendations
* Audience-Specific Perspectives

The goal is to make privacy risks easier to understand through clear visualizations and an engaging user experience.

---

## Features

### Interactive Landing Experience

* Glassmorphism-inspired interface
* Animated starfield background
* Multi-stage scan launch sequence
* Responsive design

### Visibility Dashboard

* Dynamic visibility score generation
* Animated orbital score visualization
* Public signal indicators
* Exposure risk analysis
* Actionable recommendations

### Perspective-Based Analysis

Echo provides three viewpoints:

#### Recruiter View

Highlights information that may influence hiring decisions.

#### Advertiser View

Shows how publicly available information may be used for targeting and profiling.

#### Threat Actor View

Demonstrates potential information gathering opportunities available through public exposure.

### User Experience Enhancements

* Page transition animations
* Animated score ring visualization
* Progress tracking during scans
* Interactive dashboard cards
* Hover and focus micro-interactions
* Mobile-friendly layout

---

## Technology Stack

### Frontend

* React
* Vite
* JavaScript
* CSS3

### Backend

* FastAPI
* Pydantic

### Development Tools

* Git
* GitHub
* npm

---

## Architecture

Frontend (React)
↓
API Requests
↓
FastAPI Backend
↓
Score Generation & Risk Analysis
↓
Visibility Report Response
↓
Dashboard Visualization

---

## Current Status

This project is currently an MVP (Minimum Viable Product) focused on user experience, visualization, and privacy awareness concepts.

Current report generation uses deterministic mock data based on user input to simulate visibility analysis.

---

## Planned Enhancements

* Report history and scan analytics
* MITRE ATT&CK technique mapping
* PDF report exports
* Historical report comparisons
* Real breach intelligence integrations
* Username availability scanning
* Domain and DNS security analysis
* User authentication and saved reports

---

## Motivation

Digital footprints are often difficult for users to understand. Echo aims to make privacy and exposure risks more accessible through visualization, storytelling, and actionable recommendations.

The project combines cybersecurity concepts with modern frontend engineering to create an engaging educational experience.

---

## Author

Zara Hameedi

B.S. Computer Science
Pace University
