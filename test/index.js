const assert = require('node:assert/strict')

const fixtures = require('haraka-test-fixtures')

const _set_up = () => {
  this.plugin = new fixtures.plugin('relay')
  this.plugin.cfg = {}
  this.connection = fixtures.connection.createConnection()
}

describe('relay', () => {
  describe('plugin', () => {
    beforeEach(_set_up)

    it('should have register function', () => {
      assert.ok(this.plugin)
      assert.equal('function', typeof this.plugin.register)
    })

    it('register function should call register_hook()', () => {
      this.plugin.register()
      assert.ok(this.plugin.register_hook.called)
    })
  })

  describe('load_config_files', () => {
    beforeEach(_set_up)

    it('relay.ini', () => {
      this.plugin.load_relay_ini()
      assert.ok(typeof this.plugin.cfg === 'object')
      assert.ok(this.plugin.cfg)
      assert.ok(this.plugin.cfg.relay)
    })

    it('relay_dest_domains.ini', () => {
      this.plugin.load_dest_domains()
      assert.ok(typeof this.plugin.dest === 'object')
    })
  })

  describe('is_acl_allowed', () => {
    beforeEach(_set_up)

    it('bare IP', () => {
      this.plugin.acl_allow = ['127.0.0.6']
      this.connection.remote.ip = '127.0.0.6'
      assert.equal(true, this.plugin.is_acl_allowed(this.connection))
      this.connection.remote.ip = '127.0.0.5'
      assert.equal(false, this.plugin.is_acl_allowed(this.connection))
      this.connection.remote.ip = '127.0.1.5'
      assert.equal(false, this.plugin.is_acl_allowed(this.connection))
    })

    it('netmask', () => {
      this.plugin.acl_allow = ['127.0.0.6/24']
      this.connection.remote.ip = '127.0.0.6'
      assert.equal(true, this.plugin.is_acl_allowed(this.connection))
      this.connection.remote.ip = '127.0.0.5'
      assert.equal(true, this.plugin.is_acl_allowed(this.connection))
      this.connection.remote.ip = '127.0.1.5'
      assert.equal(false, this.plugin.is_acl_allowed(this.connection))
    })

    it('mixed (ipv4 & ipv6 (Issue #428))', () => {
      this.connection.remote.ip = '2607:f060:b008:feed::2'
      assert.equal(false, this.plugin.is_acl_allowed(this.connection))

      this.plugin.acl_allow = ['2607:f060:b008:feed::2/64']
      this.connection.remote.ip = '2607:f060:b008:feed::2'
      assert.equal(true, this.plugin.is_acl_allowed(this.connection))

      this.plugin.acl_allow = ['127.0.0.6/24']
      this.connection.remote.ip = '2607:f060:b008:feed::2'
      assert.equal(false, this.plugin.is_acl_allowed(this.connection))
    })
  })

  describe('acl', () => {
    beforeEach(() => {
      this.plugin = new fixtures.plugin('relay')
      this.plugin.cfg = { relay: { dest_domains: true } }
      this.connection = fixtures.connection.createConnection()
    })

    it('relay.acl=false', async () => {
      this.plugin.cfg.relay.acl = false
      this.plugin.acl(() => {}, this.connection)
      await new Promise((resolve) => {
        this.plugin.pass_relaying((rc) => {
          assert.equal(undefined, rc)
          resolve()
        }, this.connection)
      })
    })

    it('relay.acl=true, miss', async () => {
      this.plugin.cfg.relay.acl = true
      this.plugin.acl(() => {}, this.connection)
      await new Promise((resolve) => {
        this.plugin.pass_relaying((rc) => {
          assert.equal(undefined, rc)
          assert.equal(false, this.connection.relaying)
          resolve()
        }, this.connection)
      })
    })

    it('relay.acl=true, hit', async () => {
      this.plugin.cfg.relay.acl = true
      this.connection.remote.ip = '1.1.1.1'
      this.plugin.acl_allow = ['1.1.1.1/32']
      this.plugin.acl(() => {}, this.connection)
      await new Promise((resolve) => {
        this.plugin.pass_relaying((rc) => {
          assert.equal(OK, rc)
          assert.equal(true, this.connection.relaying)
          resolve()
        }, this.connection)
      })
    })

    it('relay.acl=true, hit, missing mask', async () => {
      this.plugin.cfg.relay.acl = true
      this.connection.remote.ip = '1.1.1.1'
      this.plugin.acl_allow = ['1.1.1.1']
      this.plugin.acl(() => {}, this.connection)
      await new Promise((resolve) => {
        this.plugin.pass_relaying((rc) => {
          assert.equal(OK, rc)
          assert.equal(true, this.connection.relaying)
          resolve()
        }, this.connection)
      })
    })

    it('relay.acl=true, hit, net', async () => {
      this.plugin.cfg.relay.acl = true
      this.connection.remote.ip = '1.1.1.1'
      this.plugin.acl_allow = ['1.1.1.1/24']
      this.plugin.acl(() => {}, this.connection)
      await new Promise((resolve) => {
        this.plugin.pass_relaying((rc) => {
          assert.equal(OK, rc)
          assert.equal(true, this.connection.relaying)
          resolve()
        }, this.connection)
      })
    })
  })

  describe('dest_domains', () => {
    beforeEach(() => {
      this.plugin = new fixtures.plugin('relay')
      this.plugin.cfg = { relay: { dest_domains: true } }

      this.connection = fixtures.connection.createConnection()
      this.connection.init_transaction()
    })

    it('relay.dest_domains=false', async () => {
      this.plugin.cfg.relay.dest_domains = false
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(undefined, rc)
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('relaying', async () => {
      this.connection.relaying = true
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(undefined, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').skip.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('no config', async () => {
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(undefined, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').err.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('action=undef', async () => {
      this.plugin.dest = { domains: { foo: '{"action":"dunno"}' } }
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(DENY, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').fail.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('action=deny', async () => {
      this.plugin.dest = { domains: { foo: '{"action":"deny"}' } }
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(DENY, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').fail.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('action=continue', async () => {
      this.plugin.dest = { domains: { foo: '{"action":"continue"}' } }
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(CONT, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').pass.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })

    it('action=accept', async () => {
      this.plugin.dest = { domains: { foo: '{"action":"continue"}' } }
      await new Promise((resolve) => {
        this.plugin.dest_domains(
          (rc) => {
            assert.equal(CONT, rc)
            assert.equal(
              1,
              this.connection.transaction.results.get('relay').pass.length,
            )
            resolve()
          },
          this.connection,
          [{ host: 'foo' }],
        )
      })
    })
  })

  describe('force_routing', () => {
    beforeEach(() => {
      this.plugin = new fixtures.plugin('relay')
      this.plugin.cfg = { relay: { force_routing: true } }
      this.plugin.dest = {}

      this.connection = fixtures.connection.createConnection()
      this.connection.init_transaction()
    })

    it('relay.force_routing=false', async () => {
      this.plugin.cfg.relay.force_routing = false
      await new Promise((resolve) => {
        this.plugin.force_routing(
          (rc) => {
            assert.equal(undefined, rc)
            resolve()
          },
          this.connection,
          'foo',
        )
      })
    })

    it('dest_domains empty', async () => {
      await new Promise((resolve) => {
        this.plugin.force_routing(
          (rc) => {
            assert.equal(undefined, rc)
            resolve()
          },
          this.connection,
          'foo',
        )
      })
    })

    it('dest_domains, no route', async () => {
      this.plugin.dest = { domains: { foo: '{"action":"blah blah"}' } }
      await new Promise((resolve) => {
        this.plugin.force_routing(
          (rc, nexthop) => {
            assert.equal(undefined, rc)
            assert.equal(undefined, nexthop)
            resolve()
          },
          this.connection,
          'foo',
        )
      })
    })

    it('dest_domains, route', async () => {
      this.plugin.dest = {
        domains: { foo: '{"action":"blah blah","nexthop":"other-server"}' },
      }
      await new Promise((resolve) => {
        this.plugin.force_routing(
          (rc, nexthop) => {
            assert.equal(OK, rc)
            assert.equal('other-server', nexthop)
            resolve()
          },
          this.connection,
          'foo',
        )
      })
    })

    it('dest-domains, any', async () => {
      this.plugin.dest = {
        domains: {
          foo: '{"action":"blah blah","nexthop":"other-server"}',
          any: '{"action":"blah blah","nexthop":"any-server"}',
        },
      }
      await new Promise((resolve) => {
        this.plugin.force_routing(
          (rc, nexthop) => {
            assert.equal(OK, rc)
            assert.equal('any-server', nexthop)
            resolve()
          },
          this.connection,
          'not',
        )
      })
    })
  })

  describe('all', () => {
    beforeEach(_set_up)

    it('register_hook() should register available function', () => {
      assert.ok(this.plugin.all)
      assert.equal('function', typeof this.plugin.all)
      this.plugin.register()
      this.plugin.cfg.relay.all = true
      this.plugin.register_hook('rcpt', 'all') // register() doesn't b/c config is disabled
      // console.log(this.plugin.register_hook.args);
      assert.equal(this.plugin.register_hook.args[3][1], 'all')
    })

    it('all hook always returns OK', async () => {
      this.plugin.cfg.relay = { all: true }
      await new Promise((resolve) => {
        this.plugin.all(
          (action) => {
            assert.equal(action, OK)
            resolve()
          },
          this.connection,
          ['foo@bar.com'],
        )
      })
    })

    it('all hook always sets connection.relaying to true', async () => {
      this.plugin.cfg.relay = { all: true }
      await new Promise((resolve) => {
        this.plugin.all(
          () => {
            assert.equal(this.connection.relaying, true)
            resolve()
          },
          this.connection,
          ['foo@bar.com'],
        )
      })
    })
  })
})
