# frozen_string_literal: true
Header = Data.define(:id, :flags, :qdcount, :ancount, :nscount, :arcount) do
  def initialize(id:, flags:, qdcount: 0, ancount: 0, nscount: 0, arcount: 0)
    super
  end
end
