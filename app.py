#!flask/bin/python

from flask import Flask, jsonify, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import os
import requests
import PrbabilityCalculator
import subprocess

app = Flask(__name__)

UPLOAD_FOLDER = './static/user_files/'
ALLOWED_EXTENSIONS = set(['xml'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

'''
Some of the code is taken from https://gist.github.com/dAnjou/2874714
'''

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def analyzer(filename, alpha=1):
    return PrbabilityCalculator.calcumprob(filename,alpha)

def fault(s=''):
    print(s)
    fail_str = 'We encountered an error processing your request! Please make sure that the inputs are in the correct format and try again.'
    return render_template('index.html', message_f=fail_str)

def get_strategy(filename, budget):
    subprocess.call(["./placeids.sh", filename, budget])

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/analysis', methods=['POST'])
def getShares():
    # Save the graph file
    graph_xml = request.files['file']
    if graph_xml and allowed_file(graph_xml.filename):
        filename = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(graph_xml.filename))
        graph_xml.save(filename)
    else:
        return fault()

    # Get alpha and call analyzer function
    alpha = request.form['alpha'].strip()
    budget = request.form['budget'].strip()
    try:
        prob, cve = analyzer(filename, float(alpha))
    except:
        return fault('Problem is Risk Assessment and Countermeasure selection module.')

    try:
        get_strategy(filename, int(budget))
    except:
        print('Problem is Strategy Generation module. Check you have list of all the downstream packages. Sending old file.')

    return render_template('success.html', prob_to_goal=prob, worst_cve=cve)

@app.route('/static/user_files/output_mixed_strategy.txt')
def send_file_ms():
    return send_file('./static/user_files/output_mixed_strategy.txt',
                     attachment_filename='strategy.txt')

@app.route('/static/user_files/jsonoutput.json')
def send_file_jo():
    return send_file('./static/user_files/jsonoutput.json',
                     attachment_filename='jsonoutput.json')

if __name__ == '__main__':
    app.run(port=5000)