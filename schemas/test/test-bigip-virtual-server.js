/*-
 * Copyright 2016 F5 Networks Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 *          software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *            implied.
 * See the License for the specific language governing permissions
 *             and
 * limitations under the License.
 */
'use strict';

const SchemaHandler = require('./util').SchemaHandler;
const handleError = require('./util').handleError;

handleError();

const CURRENT_VERSION="v0.1.4";
const testSchema = `f5schemadb://bigip-virtual-server_${CURRENT_VERSION}.json`;

exports.bigipVirtualServer = {
  setUp: cb => {
    let baseUri = __dirname + '/..';
    this.sUtil = new SchemaHandler(baseUri);

    this.baseValidConfig = {
      "virtualServer": {
        "frontend": {
          "virtualAddress": {
            "bindAddr": "127.0.0.1",
            "port": 5050
          },
          "partition": "velcro-partition",
          "mode": "http",
          "balance": "round-robin",
          "sslProfile": {
            "f5ProfileName": "f5-bigip-profile-name"
          }
        },
        "backend": {
          "serviceName": "kubernetes-service",
          "servicePort": 80,
          "healthMonitors": [ {
            "interval": 30,
            "timeout": 10,
            "protocol": "tcp",
            "send": "/"
          } ]
        }
      }
    };

    this.baseValidConfigMultiSslProfiles = {
      "virtualServer": {
        "frontend": {
          "virtualAddress": {
            "bindAddr": "127.0.0.1",
            "port": 5050
          },
          "partition": "velcro-partition",
          "mode": "http",
          "balance": "round-robin",
          "sslProfile": {
            "f5ProfileNames": [
              "f5-bigip-profile-name1",
              "f5-bigip-profile-name2"
            ]
          }
        },
        "backend": {
          "serviceName": "kubernetes-service",
          "servicePort": 80,
          "healthMonitors": [ {
            "interval": 30,
            "timeout": 10,
            "protocol": "tcp",
            "send": "/"
          } ]
        }
      }
    };

    this.baseIAppConfig = {
      "virtualServer": {
        "frontend": {
          "iapp": "iApp-Template",
          "partition": "velcro-partition",
          "iappPoolMemberTable": {
            "name": "pool__members",
            "columns": [
              {"name": "IPAddress", "kind": "IPAddress"},
              {"name": "Port", "kind": "Port"},
              {"name": "ConnectionLimit", "value": "0"},
              {"name": "SomeOtherValue", "value": "value-1"},
              {"name": "YetAnotherValue", "value": "value2"}
            ]
          },
          "iappOptions": {
            "test": "test",
            "underscore_test": "underscore",
            "dash-test": "dash",
            "CAPS_test": "caps",
            "Alpha-Numeric-0-1-2-3-4-5-6-7-8-9": "alphanumeric"
          },
          "iappTables": {
            "table1": {
              "columns": ["one", "two", "three"],
              "rows": [["0", "", "round-robin"]]
            },
            "table_2": {
              "columns": ["1", "two", "three"],
              "rows": [["0", "", "none"], ["1", "val", ""]]
            }
          },
          "iappVariables": {
            "test": "test",
            "underscore_test": "underscore",
            "dash-test": "dash",
            "CAPS_test": "caps",
            "Alpha-Numeric-0-1-2-3-4-5-6-7-8-9": "alphanumeric"
          }
        },
        "backend": {
          "serviceName": "kubernetes-service",
          "servicePort": 80
        }
      }
    };

    cb();
  },
  tearDown: cb => {
    cb();
  }
}

exports.bigipVirtualServer.valid = t => {
  let data = Object.assign({}, this.baseValidConfig);
  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a valid result');

    data = Object.assign({}, this.baseIAppConfig);
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a valid result');

    t.done();
  });
};

exports.bigipVirtualServer.validMultiSslProfiles = t => {
  let data = Object.assign({}, this.baseValidConfigMultiSslProfiles);
  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a valid result');

    data = Object.assign({}, this.baseIAppConfig);
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a valid result');

    t.done();
  });
};

exports.bigipVirtualServer.mutualExclusiveFrontend = t => {
  let data = Object.assign({}, this.baseIAppConfig);
  data.virtualServer.frontend.virtualAddress = {
    'bindAddr': '127.0.0.1',
    'port': 50505
  };

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for empty partition');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.missingVirtualAddress = t => {
  let data = Object.assign({}, this.baseValidConfig);
  delete data.virtualServer.frontend.virtualAddress

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should be allowed to have a blank virtualAddress')
    t.done()
  });
};

exports.bigipVirtualServer.invalidPartition = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.partition = '';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for empty partition');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    data.virtualServer.frontend.partition = 5555;

    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for invalid partition');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.invalidMode = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.mode = 'not tcp or http';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.invalidBalance = t => {

  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.balance = 'least-weighted-conns';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.invalidBindAddr = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.virtualAddress.bindAddr = 'http://example.com';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.validBindAddr = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.virtualAddress.bindAddr = '127.1.1.1';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have been valid');
    t.done();
  });
};

exports.bigipVirtualServer.validBindAddrRouteDomain = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.virtualAddress.bindAddr = '127.1.1.1%44';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have been valid');
    t.done();
  });
};

exports.bigipVirtualServer.invalidBindAddrRouteDomain = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.virtualAddress.bindAddr = '127%44';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');
    t.done();
  });
};

exports.bigipVirtualServer.invalidPort = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.virtualAddress.port = 0;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    data.virtualServer.frontend.virtualAddress.port = 65536;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    data.virtualServer.frontend.virtualAddress.port = "not an int";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.invalidSslProfile = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.frontend.sslProfile.f5ProfileName = 5555;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for empty profile');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.missingFrontendRequired = t => {
  let data = Object.assign({}, this.baseValidConfig);
  delete data.virtualServer.frontend.partition;
  delete data.virtualServer.frontend.virtualAddress;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have error');

    data = Object.assign({}, this.baseValidConfig);
    delete data.virtualServer.frontend.partition;

    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have required failure');

    t.done();
  });
};

exports.bigipVirtualServer.missingVSRequired = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer = {};

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 2, 'Should have two errors');

    t.done();
  });
};

exports.bigipVirtualServer.missingBackendRequired = t => {
  let data = Object.assign({}, this.baseValidConfig);
  delete data.virtualServer.backend.serviceName;
  delete data.virtualServer.backend.servicePort;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 2, 'Should have two errors');

    t.done();
  });
};

exports.bigipVirtualServer.invalidServiceName = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.backend.serviceName = '';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for empty serviceName');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.serviceName',
        'Should have serviceName error');
    t.strictEqual(result.errors[0].message,
        'does not meet minimum length of 1', 'Should have empty string error');

    data.virtualServer.backend.serviceName = 5555;

    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for invalid serviceName');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.serviceName',
        'Should have serviceName error');
    t.strictEqual(result.errors[0].message,
        'is not of a type(s) string', 'Should have non string error');

    t.done();
  });
};

exports.bigipVirtualServer.invalidServicePort = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.backend.servicePort = 0;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.servicePort',
        'Should have port error');
    t.strictEqual(result.errors[0].message,
        'must have a minimum value of 1', 'Should have minimum error');

    data.virtualServer.backend.servicePort = 65536;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.servicePort',
        'Should have port error');
    t.strictEqual(result.errors[0].message,
        'must have a maximum value of 65535', 'Should have maximum error');

    data.virtualServer.backend.servicePort = "not an int";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.servicePort',
        'Should have port error');
    t.strictEqual(result.errors[0].message,
        'is not of a type(s) integer', 'Should have non integer error');

    t.done();
  });
};

exports.bigipVirtualServer.invalidHealthMonitor = t => {
  let data = Object.assign({}, this.baseValidConfig);
  data.virtualServer.backend.healthMonitors[0].interval = 0;

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].interval',
        'Should have interval error');
    t.strictEqual(result.errors[0].message,
        'must have a minimum value of 1', 'Should have minimum error');

    data.virtualServer.backend.healthMonitors[0].interval = 86401;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].interval',
        'Should have interval error');
    t.strictEqual(result.errors[0].message,
        'must have a maximum value of 86400', 'Should have maximum error');

    data.virtualServer.backend.healthMonitors[0].interval = "not an int";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].interval',
        'Should have interval error');
    t.strictEqual(result.errors[0].message,
        'is not of a type(s) integer', 'Should have non integer error');

    data.virtualServer.backend.healthMonitors[0].interval = 30;
    data.virtualServer.backend.healthMonitors[0].timeout = 0;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].timeout',
        'Should have timeout error');
    t.strictEqual(result.errors[0].message,
        'must have a minimum value of 1', 'Should have minimum error');

    data.virtualServer.backend.healthMonitors[0].timeout = 86401;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].timeout',
        'Should have timeout error');
    t.strictEqual(result.errors[0].message,
        'must have a maximum value of 86400', 'Should have maximum error');

    data.virtualServer.backend.healthMonitors[0].timeout = "not an int";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].timeout',
        'Should have timeout error');
    t.strictEqual(result.errors[0].message,
        'is not of a type(s) integer', 'Should have non integer error');

    data.virtualServer.backend.healthMonitors[0].timeout = 10;
    data.virtualServer.backend.healthMonitors[0].protocol = "icmp";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].protocol',
        'Should have protocol error');
    t.strictEqual(result.errors[0].message,
        'is not one of enum values: http,tcp', 'Should have non enum error');

    data.virtualServer.backend.healthMonitors[0].protocol = "tcp";
    data.virtualServer.backend.healthMonitors[0].send = "";
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].send',
        'Should have send error');
    t.strictEqual(result.errors[0].message,
        'does not meet minimum length of 1', 'Should have min length error');

    data.virtualServer.backend.healthMonitors[0].send = 1;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[0].send',
        'Should have send error');
    t.strictEqual(result.errors[0].message,
        'is not of a type(s) string', 'Should have non string error');

    data.virtualServer.backend.healthMonitors[0].send = "GET /";

    // Undefined index
    try {
        data.virtualServer.backend.healthMonitors[1].send = "GET /";
    } catch (err) {
        t.strictEqual(err.message, 'Cannot set property \'send\' of undefined');
    }

    // Add a second health monitor, missing protocol
    var anotherHM = { 'send': 'GET /', 'interval': 20, 'timeout': 16 };
    data.virtualServer.backend.healthMonitors[1] = anotherHM;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.backend.healthMonitors[1]',
        'Should have send error');
    t.strictEqual(result.errors[0].message,
        'requires property "protocol"', 'Should have missing protocol');

    anotherHM = { 'send': 'GET /', 'interval': 20, 'timeout': 16,
                  'protocol': 'http' };
    data.virtualServer.backend.healthMonitors[1] = anotherHM;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should be a success');

    t.done();
  });
};

exports.bigipVirtualServer.invalidIApp = t => {
  let data = Object.assign({}, this.baseIAppConfig);
  data.virtualServer.frontend.iapp = '';

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for empty iapp');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    data.virtualServer.frontend.iapp = 5555;

    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for invalid iapp');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.patternOptions = t => {
  let data = Object.assign({}, this.baseIAppConfig);
  data.virtualServer.frontend.iappOptions = {};

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a success for empty iapp options');

    data.virtualServer.frontend.iappOptions.emptyOption = '';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp options');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    delete data.virtualServer.frontend.iappOptions.emptyOption;
    data.virtualServer.frontend.iappOptions[''] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp options');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    delete data.virtualServer.frontend.iappOptions[''];
    data.virtualServer.frontend.iappOptions['invalid-!@#$%^&*()'] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp options');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.patternVariables = t => {
  let data = Object.assign({}, this.baseIAppConfig);
  data.virtualServer.frontend.iappVariables = {};

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a success for empty iapp variables');

    data.virtualServer.frontend.iappVariables.emptyOption = '';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp variables');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    delete data.virtualServer.frontend.iappVariables.emptyOption;
    data.virtualServer.frontend.iappVariables[''] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp variables');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    delete data.virtualServer.frontend.iappVariables[''];
    data.virtualServer.frontend.iappVariables['invalid-!@#$%^&*()'] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp variables');

    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};

exports.bigipVirtualServer.patternTables = t => {
  let data = Object.assign({}, this.baseIAppConfig);

  this.sUtil.loadSchemas(testSchema, () => {
    // Table with no columns
    delete data.virtualServer.frontend.iappTables['table1'].columns;
    let result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Table with no rows
    data.virtualServer.frontend.iappTables['table1'].columns = ['a', 'b'];
    delete data.virtualServer.frontend.iappTables['table_2'].rows;
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Table with empty columns
    data.virtualServer.frontend.iappTables['table1'].columns = [];
    data.virtualServer.frontend.iappTables['table_2'].rows = [['a', 'b']];
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Invalid type (not an array)
    data.virtualServer.frontend.iappTables['table1'].rows = [['a', 'b']];
    data.virtualServer.frontend.iappTables['table1'].columns = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Invalid type (not an array)
    data.virtualServer.frontend.iappTables['table1'].rows = 'fail';
    data.virtualServer.frontend.iappTables['table1'].columns = ['a', 'b'];
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Invalid type (not a table)
    data.virtualServer.frontend.iappTables['table1'] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Invalid chars
    data.virtualServer.frontend.iappTables['invalid-!@#$%^&*()'] = 'fail';
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // Valid tables
    delete data.virtualServer.frontend.iappTables['invalid-!@#$%^&*()']
    data.virtualServer.frontend.iappTables['table1'] =
        {'columns': ['a', 'b', 'c'], 'rows': [['one', 'two', 'three']]}
    data.virtualServer.frontend.iappTables['table_2'] =
        {'columns': ['a', 'b', 'c'],
         'rows': [['one', 'two', 'three'], ['a1', 'a2', 'a3']]}
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have no failure for iapp tables');
    t.strictEqual(result.errors.length, 0, 'Should have no error');

    // Zero-length element in column
    data.virtualServer.frontend.iappTables['table1'] =
        {'columns': ['a', '', 'c'], 'rows': [['one', 'two', 'three']]}
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for iapp tables');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // No iApp tables
    delete data.virtualServer.frontend.iappTables
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have a success for no iapp tables');

    t.done();
  });
};

exports.bigipVirtualServer.iAppPoolMemberTable = t => {
  let data = Object.assign({}, this.baseIAppConfig);

  this.sUtil.loadSchemas(testSchema, () => {
    let result = this.sUtil.runValidate(data, testSchema);

    // No name
    delete data.virtualServer.frontend.iappPoolMemberTable.name
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for no name');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // No columns
    data.virtualServer.frontend.iappPoolMemberTable['name'] = 'pool__members';
    delete data.virtualServer.frontend.iappPoolMemberTable.columns
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for no columns');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    // No Values OK
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'IPAddress', 'kind': 'IPAddress' },
         { 'name': 'Port', 'kind': 'Port' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have no failure for no values');

    // Invalid kind
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'IPAddress', 'kind': 'ip_addr' },
         { 'name': 'Port', 'kind': 'Port' },
         { 'name': 'ConnectionLimit', 'value': '0' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have failure for invalid kind');

    // Invalid column
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'IPAddress', 'kind': 'IPAddress' },
         { 'name': 'Port', 'kind': 'Port' },
         { 'name': 'ConnectionLimit', 'parameter': '0' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have failure for invalid column');

    // Invalid column
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'IPAddress', 'kind': 'IPAddress' },
         { 'name': 'Port', 'kind': 'Port' },
         { 'nombre': 'ConnectionLimit', 'value': '0' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have failure for invalid column');

    // Column order doesn't matter
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'IPAddress', 'kind': 'IPAddress' },
         { 'name': 'Port', 'kind': 'Port' },
         { 'name': 'ConnectionLimit', 'value': '0' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have no failure for column order');
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'Port', 'kind': 'Port' },
         { 'name': 'IPAddress', 'kind': 'IPAddress' },
         { 'name': 'ConnectionLimit', 'value': '0' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have no failure for column order');
    data.virtualServer.frontend.iappPoolMemberTable.columns =
       [ { 'name': 'ConnectionLimit', 'value': '0' },
         { 'name': 'Port', 'kind': 'Port' },
         { 'name': 'IPAddress', 'kind': 'IPAddress' } ]
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(result.valid, 'Should have no failure for column order');

    // No pool-member table
    delete data.virtualServer.frontend.iappPoolMemberTable
    result = this.sUtil.runValidate(data, testSchema);
    t.ok(!result.valid, 'Should have a failure for no pool-member table');
    t.strictEqual(result.errors.length, 1, 'Should have one error');
    t.strictEqual(result.errors[0].property,
        'instance.virtualServer.frontend');
    t.strictEqual(result.errors[0].message,
        'is not exactly one from <#/definitions/frontendIAppType>,' +
        '<#/definitions/frontendVSType>');

    t.done();
  });
};
