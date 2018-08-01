#!/bin/bash

# Generate utility values by calling CVSS website
cd ./IDS_placement
python driver.py '..\static\user_files\AttackGraph.xml' '3'
cp ./BSSG_input.txt ./ResourcesHomogeneousScheduleSingleton/BSSG_input.txt

# Run optimization solver to generate equilibrium
cd ./ResourcesHomogeneousScheduleSingleton
python strategy_generator.py

cd ../../
cp ./IDS_placement/ResourcesHomogeneousScheduleSingleton/output_mixed_strategy.txt ./static/user_files/output_mixed_strategy.txt
cp ./jsonoutput.txt ./static/user_files/jsonoutput.json
