local typedefs = require "kong.db.schema.typedefs"

return {
  -- name is required here
  name = "custom-request-transformer",
  fields = {
    {
      -- this plugin will only be applied to Services or Routes
      consumer = typedefs.no_consumer
    },
    {
      -- this plugin will only run within Nginx HTTP module
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          {
            remove = {
              type = "record",
              required = false,
              fields = {
                {
                    headers = {
                      type = "array",
                      required = true,
                      default = {},
                      elements = {
                        type = "string"
                      },
                    }
                  }
              }
            }
          }
        }
      }
    }
  }
}
