# User Guide

## 1. Initial Administrator setup

On the first launch, open `/setup` and create the first Administrator account. Public registration is not provided. The password must contain at least eight characters.

## 2. Sign in and dashboard

Sign in with the account created during setup. The dashboard presents incident records, severity statistics, and the latest dataset-processing status. Newly detected incidents are saved as records are processed; the dashboard periodically requests updates while it is open.

## 3. Incident investigation

Open an incident to review its category, severity, source information, matched detection rules, and comments.

The supported status lifecycle is strictly sequential:

1. New → In Progress
2. In Progress → Resolved
3. Resolved → Closed

The backend validates each transition. Skipping a state or changing a Closed incident is rejected. An authorised user can adjust severity and add investigation comments.

## 4. Administrator functions

The Administrator can:
- create and delete user accounts;
- assign or change account roles;
- enable or disable existing detection rules.

Disabling a rule affects future dataset detections. It does not delete previously created incidents or their investigation history.

## 5. Security Analyst functions

The Security Analyst can:
- view the dashboard and incident details;
- investigate incidents;
- change incident status and severity;
- add comments.

Administrative user and detection-rule management pages are restricted to the Administrator.

## 6. Sign out

Use the sign-out control in the interface. State-changing form submissions, including sign-out, require a session CSRF token.
