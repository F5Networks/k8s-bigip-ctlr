#!/bin/bash

# Description: This script recursively searches the folder starting at FILEPATH
# for all Copyright notices and both formats and updates them to extend from the
# first year listed to the year provided by the user

# Defines relative path from this file to top of directory where a recursive
# copyright update will be performed
FILEPATH="../"

printf "\nAll instances of Copyright notices:\n":
# Saves the grep command in a variable since it is called multiple times
GCMD=$(grep -r -n --exclude-dir=".git" --exclude="update-copyright.sh" "Copyright (*[cC]*)* *20" $FILEPATH | grep "F5 Networks")
# Displays all Copyright lines excluding those in the .git folder and saves these output lines to GREPOUT
GREPOUT=$(echo "$GCMD")
echo "$GREPOUT"
# Displays the number of Copyright lines
printf "Number of found Copyright lines: "
echo "$GREPOUT" | wc -l

# Allow user to stop after searching for Copyright notices
read -n1 -p "
Update copyright notices listed above? (y/n)
" ANS
case $ANS in
  y|Y) ;;
  *) exit ;;
esac

# Allows the user to enter the year to which they wish to have the Copyright notices extended
printf "\nEnter the year you would like to add to the Copyright notices:"
read YEAR

printf "\nUpdating Copyrights...\n"

# Search for all instances of "Copyright 20**" and "Copyright (c) 20**"
echo "$GREPOUT" | while read -r line
# Updates all Copyright notices and replaces for matching syntax
do
  FIRSTYEAR=$(echo "$line" | grep -E -o -m 1 '20[0-9]{2}' | head -1)
  REPLACE=$(echo "$line" | cut -d: -f3 | sed 's/^.*Copyright/Copyright/' | sed 's/Inc\..*/Inc\./')
  #Already includes the current year and no other year
  if [[ $line = *$YEAR* && $YEAR == $FIRSTYEAR ]]; then
    echo "$line" | cut -d: -f1 | xargs sed -i '' "s/$REPLACE/Copyright\ (c)\ $YEAR,\ F5\ Networks,\ Inc./"
  #Already includes the current year and the previous year
  elif [[ $line == *$YEAR* && $YEAR -eq $((FIRSTYEAR + 1)) ]]; then
    echo "$line" | cut -d: -f1 | xargs sed -i '' "s/$REPLACE/Copyright\ (c)\ $FIRSTYEAR,$YEAR,\ F5\ Networks,\ Inc./"
  #Already includes the current year in a range
  elif [[ $line == *$YEAR* && $YEAR -gt $((FIRSTYEAR + 1)) ]]; then
    echo "$line" | cut -d: -f1 | xargs sed -i '' "s/$REPLACE/Copyright\ (c)\ $FIRSTYEAR-$YEAR,\ F5\ Networks,\ Inc./"
  #Only includes the previous year
  elif [[ $line != *$YEAR* && $YEAR -eq $((FIRSTYEAR + 1)) ]]; then
    echo "$line" | cut -d: -f1 | xargs sed -i '' "s/$REPLACE/Copyright\ (c)\ $FIRSTYEAR,$YEAR,\ F5\ Networks,\ Inc./"
  #Only includes a year earlier than the previous year
  elif [[ $line != *$YEAR* && $YEAR -gt $((FIRSTYEAR + 1)) ]]; then
    echo "$line" | cut -d: -f1 | xargs sed -i '' "s/$REPLACE/Copyright\ (c)\ $FIRSTYEAR-$YEAR,\ F5\ Networks,\ Inc./"
  fi
done

printf "\nAll instances of Copyright notices after update:\n":
# Displays all updated Copyright lines excluding those in the .git folder
GREPOUT=$(echo "$GCMD")
echo "$GREPOUT"
# Displays the number of Copyright lines
printf "Number of found Copyright lines: "
echo "$GREPOUT" | wc -l
