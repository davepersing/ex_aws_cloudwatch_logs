defmodule ExAws.LogsTest do
  use ExUnit.Case
  doctest ExAws.Logs

  test "greets the world" do
    assert ExAws.Logs.hello() == :world
  end
end
