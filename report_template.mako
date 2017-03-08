<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Scan Result</title>
    <style>
        .host {
            border: 1px #dddddd;
            border-bottom-style: solid;
            padding: 20px;
        }

        .host:first-child {
            border-top-style: solid;
        }

        .host > * {
            display: inline-block;
            vertical-align: top;
        }

        .host-ip {
            font-weight: bold;
            min-width: 120px;
        }

        .host table {
            border: 1px #dddddd;
            border-style: solid none;
        }

        .host table {
            margin: -5px;
            border-collapse: collapse;
        }

        tr:nth-child(even) {
            background-color: #f2f2f2
        }

        .port {
            min-width: 70px;
        }
    </style>
</head>
<body>
    <%
        from collections import defaultdict
        result_hosts = defaultdict(list)
        for sent, recv in results:
            result_hosts[sent.dst].append(response_format(sent, recv)[0::2])
        for packets in result_hosts.values():
            packets.sort()
    %>

<h1>Scan Results</h1>
<p>${len(result_hosts)} hosts responded.</p>
<div class="results">
    % for dst, packets in sorted(result_hosts.items()):
        <div class="host">
            <div class="host-ip">${dst}</div>
            <table>
                % for port, state in packets:
                    <tr>
                        <td class="port">${port}</td>
                        <td class="state">${state}</td>
                    </tr>
                % endfor
            </table>
        </div>
    % endfor
</div>
</body>
</html>