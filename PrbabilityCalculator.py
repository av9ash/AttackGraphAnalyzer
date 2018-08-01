import networkx as nx
import matplotlib.pyplot as plt
import xml.etree.cElementTree as ET

from flask import Flask,jsonify

app = Flask(__name__)


@app.route('/')
def calcumprob(filename="adata.xml",alpha=0.5):
    from pymongo import MongoClient
    client = MongoClient()
    db = client.cvedb
    collection = db.cves

    G = nx.DiGraph()
    tree = ET.parse(filename)
    root = tree.getroot()
    vertices = root.find('vertices')
    arcs = root.find('arcs')
    leafs = []
    vulnodes = []
    delta = []
    cveids = []
    output = []

    for arc in arcs.findall('arc'):
        # print (arc.find('src').text,arc.find('dst').text)
        if arc.find('dst').text != "1":
            G.add_edge(arc.find('src').text, arc.find('dst').text)

    for vertex in vertices:
        # print (vertex.find('id').text,vertex.find('fact').text,
        # vertex.find('metric').text,vertex.find('type').text)
        if vertex.find('type').text == 'LEAF':
            if 'attackerLocated' in vertex.find('fact').text:
                attacker = vertex.find('id').text
            else:
                leafs.append(vertex.find('id').text)

        basescore = 1  # do not move from here

        # Following code is not needed but it helps in undrestanding and making changess
        if vertex.find('type').text == 'OR':
            basescore = 1

        if vertex.find('type').text == 'AND':
            basescore = 1

        if vertex.find('type').text == 'LEAF':
            basescore = alpha

        if 'vulExists' in vertex.find('fact').text:
            fact = vertex.find('fact').text.split(',')
            vul = collection.find_one({"id": fact[1].replace("'", "")})
            basescore = vul.get('cvss', -1) / 10
            vertex.set('score', basescore)
            vulnodes.append(vertex.find('id').text)
            cveids.append(vertex.find('id').text + ': ' + vul.get('id'))

        G.add_node(vertex.find('id').text, fact=vertex.find('fact').text,
                   metric=vertex.find('metric').text, type=vertex.find('type').text,
                   basescore=basescore, solved=False)

    G.nodes(data=True)
    G.remove_node(attacker)

    # G.node['52']['basescore'] = 0.8
    G = G.reverse(True)
    # use only copies of actual graph
    G1 = G.copy()

    prob1 = solve(G1, '1', [], [],output)

    for item in output:
        print (item)

    # calcuate delta
    for vul in vulnodes:
        G2 = G.copy()
        G2.node[vul]['basescore'] = 0.005
        tdelta = prob1 - solve(G2, '1', [],[],output)
        delta.append({'vul': vul, 'delta': tdelta})

    # print(list(delta))
    maxdelta = max(delta, key=lambda x: x['delta'])

    nx.draw(G, with_labels=True)
    # plt.show()
    plt.savefig("path.png")

    cveid = ''
    for item in cveids:
        if maxdelta['vul'] in item:
            cveid = item

    import json
    with open('jsonoutput.txt', 'w+') as outfile:
        json.dump(output, outfile)

    return prob1,cveid
    # return jsonify(output,{"Cumulative Probability":prob1},{"CVEID":cveid})

def solve(G, node, coverednodes, path,output):
    if node in coverednodes:
        return G.node[node]['basescore']
    else:
        coverednodes.append(node)
        path.append(node)

    if G.node[node]['type'] == "LEAF":
        vx = "Not a VulExists"
        if "vulExists" in G.node[node]['fact']:
            vx = "VulExists"

        dicto = {"Path":','.join(map(str, coverednodes)),"Probability":G.node[node]['basescore'],"Type":G.node[node]['type'],"Property":vx}
        output.append(dicto)

        coverednodes.pop()
        return round(G.node[node]['basescore'],3)

    else:
        if G.node[node]['type'] == "OR":
            for predecessor in sorted(G.predecessors(node)):
                G.node[node]['basescore'] = (G.node[node]['basescore'])*(1-solve(G,predecessor,coverednodes,path,output))

            dicto = {"Path": ','.join(map(str, coverednodes)), "Probability": 1 - round(G.node[node]['basescore'],3), "Type": G.node[node]['type'],
                     "Property": "Rule"}

            # output.append(dicto)

            coverednodes.pop()
            return 1 - round(G.node[node]['basescore'],3)
        else:
            for predecessor in sorted(G.predecessors(node)):
                G.node[node]['basescore'] = (G.node[node]['basescore'])*(solve(G,predecessor,coverednodes,path,output))

            dicto = {"Path": ','.join(map(str, coverednodes)), "Probability": round(G.node[node]['basescore'], 3),
                     "Type": G.node[node]['type'],
                     "Property": "Rule"}

            # output.append(dicto)
            coverednodes.pop()
            return round(G.node[node]['basescore'],3)


if __name__ == '__main__':
    app.run(port=8080)