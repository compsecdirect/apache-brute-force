#!/bin/bash
# Config file template. Please fill in with your own values!

# AWS settings
export PROFILE_NAME="AWS-CLI-PROFILE-NAME"

# IP set settings
#IPV4 list
export IP_SET_NAME=""
export IP_SET_REGION=""
export IP_SET_ID=""
#IPV6 list
export IP_SET_V6NAME=""
export IP_SET_V6REGION=""
export IP_SET_ID_IPV6=""

# Web ACL settings
#IPV4
export WEB_ACL_NAME=""
export WEB_ACL_REGION=""
#IPV6
export WEB_ACL_V6NAME=""
export WEB_ACL_V6REGION=""

# Resouce ARN. Resource you will apply the WEB ACL to. Do not use default. 
export RESOURCE_ARN="arn:aws:elasticloadbalancing:region:account-id:loadbalancer/......"



