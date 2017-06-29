#!/usr/bin/env python

# Copyright 2017 F5 Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Python script to convert coveralls-python data into goveralls format."""

import json
import sys

datafile = sys.argv[1]

base = 'github.com/F5Networks/k8s-bigip-ctlr/python/'
result = ''

with open(datafile) as myfile:
    mydata = json.load(myfile)

for source_file in mydata['source_files']:
    if len(source_file['coverage']) == 0:
        continue
    filename = source_file['name']
    for index in range(len(source_file['coverage'])):
        line_num = index + 1
        covered = source_file['coverage'][index]
        if type(covered) != int:
            continue
        result += "%s%s:%i.1,%i.1 1 %i\n" % (
            base,
            filename,
            line_num,
            line_num,
            covered
        )

with open(sys.argv[2], 'w') as goveralls_data:
    goveralls_data.write(result)
