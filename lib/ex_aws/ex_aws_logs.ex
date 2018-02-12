defmodule ExAws.Logs do
  @moduledoc """
  ExAws service to interact with Cloudwatch Logs.
  """

  @version "2014-03-28"
  @namespace "Logs_20140328"

  import ExAws.Utils, only: [camelize_keys: 1]

  @doc "Associate a KMS key"
  @spec associate_kms_key(kms_key_id :: binary(), log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def associate_kms_key(kms_key_id, log_group_name) do
    query_params = %{
      "Action" => "AssociateKmsKey",
      "Version" => @version,
      "kmsKeyId" => kms_key_id,
      "logGroupName" => log_group_name
    }

    request(:associate_kms_key, query_params)
  end

  @doc "Cancel an export task"
  @spec cancel_export_task(task_id :: binary()) :: ExAws.Operation.JSON.t()
  def cancel_export_task(task_id) do
    query_params = %{
      "Action" => "CancelExportTask",
      "Version" => @version,
      "taskId" => task_id
    }

    request(:cancel_export_task, query_params)
  end

  @doc "Create an export task"
  @type create_export_task_opt :: [
    {:destination_prefix, binary()},
    {:log_stream_name_prefix, binary()},
    {:task_name, binary()}
  ]

  @spec create_export_task(
    destination :: binary(),
    from :: pos_integer(),
    log_group_name :: binary(),
    to :: pos_integer()) :: ExAws.Operation.JSON.t()
  @spec create_export_task(
    destination :: binary(),
    from :: pos_integer(),
    log_group_name :: binary(),
    to :: pos_integer(),
    opts :: create_export_task_opt()) :: ExAws.Operation.JSON.t()
  def create_export_task(destination, from, log_group_name, to, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "CreateExportTask",
      "Version" => @version,
      "destination" => destination,
      "from" => from,
      "logGroupName" => log_group_name,
      "to" => to
    })

    request(:create_export_task, query_params)
  end

  @doc "Create log group"
  @type create_log_group_opt :: [
    {:kms_key_id, binary()},
    {:tags, [{binary(), binary()}]}
  ]

  @spec create_log_group(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  @spec create_log_group(log_group_name :: binary(), opts :: create_log_group_opt()) :: ExAws.Operation.JSON.t()
  def create_log_group(log_group_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "CreateLogGroup",
      "Version" => @version,
      "logGroupName" => log_group_name
      })

    request(:create_log_group, query_params)
  end

  @doc "Create log stream"
  @spec create_log_stream(log_group_name :: binary(), log_stream_name :: binary()) :: ExAws.Operation.JSON.t()
  def create_log_stream(log_group_name, log_stream_name) do
    query_params = %{
      "Action" => "CreateLogStream",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "logStreamName" => log_stream_name
    }

    request(:create_log_stream, query_params)
  end

  @doc "Delete destination"
  @spec delete_destination(destination_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_destination(destination_name) do
    query_params = %{
      "Action" => "DeleteDestination",
      "Version" => @version,
      "destinationName" => destination_name
    }

    request(:delete_destination, query_params)
  end

  @doc "Delete log group"
  @spec delete_log_group(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_log_group(log_group_name) do
    query_params = %{
      "Action" => "DeleteLogGroup",
      "Version" => @version,
      "logGroupName" => log_group_name
    }

    request(:delete_log_group, query_params)
  end

  @doc "Delete log stream"
  @spec delete_log_stream(log_group_name :: binary(), log_stream_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_log_stream(log_group_name, log_stream_name) do
    query_params = %{
      "Action" => "DeleteLogStream",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "logStreamName" => log_stream_name
    }

    request(:delete_log_stream, query_params)
  end

  @doc "Delete metric filter"
  @spec delete_metric_filter(filter_name :: binary(), log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_metric_filter(filter_name, log_group_name) do
    query_params = %{
      "Action" => "DeleteMetricFilter",
      "Version" => @version,
      "filterName" => filter_name,
      "logGroupName" => log_group_name
    }

    request(:delete_metric_filter, query_params)
  end

  @doc "Delete resource policy"
  @spec delete_resource_policy(policy_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_resource_policy(policy_name) do
    query_params = %{
      "Action" => "DeleteResourcePolicy",
      "Version" => @version,
      "policyName" => policy_name
    }

    request(:delete_resource_policy, query_params)
  end

  @doc "Delete retention policy"
  @spec delete_retention_policy(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_retention_policy(log_group_name) do
    query_params = %{
      "Action" => "DeleteRetentionPolicy",
      "Version" => @version,
      "logGroupName" => log_group_name
    }

    request(:delete_retention_policy, query_params)
  end

  @doc "Delete subscription filter"
  @spec delete_subscription_filter(filter_name :: binary(), log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def delete_subscription_filter(filter_name, log_group_name) do
    query_params = %{
      "Action" => "DeleteSubscriptionFilter",
      "Version" => @version,
      "filterName" => filter_name,
      "logGroupName" => log_group_name
    }

    request(:delete_subscription_filter, query_params)
  end

  @doc "Describe destinations"
  @type describe_destination_opt :: [
    {:destination_name_prefix, binary()},
    {:limit, pos_integer()},
    {:next_token, binary()}
  ]

  @spec describe_destinations() :: ExAws.Operation.JSON.t()
  @spec describe_destinations(opts :: describe_destination_opt()) :: ExAws.Operation.JSON.t()
  def describe_destinations(opts \\ []) do
    # DestinationNamePrefix is upper CamelCase, the rest are not.  :|
    query_params = opts
    |> normalize_opts()
    |> Enum.reduce(%{},
      fn({k, v}, acc) ->
        case k do
          "destinationNamePrefix" -> Map.put(acc, "DestinationNamePrefix", v)
          _ -> Map.put(acc, k, v)
        end
    end)
    |> Map.merge(%{
      "Action" => "DescribeDestinations",
      "Version" => @version
    })

    request(:describe_destinations, query_params)
  end

  @doc "Describe export tasks"
  @type status_code_t :: :CANCELLED | :COMPLETED | :FAILED | :PENDING | :PENDING_CANCEL | :RUNNING
  @type describe_export_tasks_opt :: [
    {:limit, pos_integer()},
    {:next_token, binary()},
    {:status_code, status_code_t()},
    {:task_id, binary()}
  ]

  @spec describe_export_tasks() :: ExAws.Operation.JSON.t()
  @spec describe_export_tasks(opts :: describe_export_tasks_opt()) :: ExAws.Operation.JSON.t()
  def describe_export_tasks(opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeExportTasks",
      "Version" => @version
      })

    request(:describe_export_tasks, query_params)
  end

  @doc "Describe log groups"
  @type describe_log_groups_opt :: [
    {:limit, pos_integer()},
    {:log_group_name_prefix, binary()},
    {:next_token, binary()}
  ]

  @spec describe_log_groups() :: ExAws.Operation.JSON.t()
  @spec describe_log_groups(opts :: describe_log_groups_opt()) :: ExAws.Operation.JSON.t()
  def describe_log_groups(opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeLogGroups",
      "Version" => @version
    })

    request(:describe_log_groups, query_params)
  end

  @doc "Describe log streams"
  @type order_by_t :: :LogStreamName | :LastEventTime

  @type describe_log_streams_opt :: [
    {:descending, boolean()},
    {:limit, pos_integer()},
    {:log_stream_name_prefix, binary()},
    {:next_token, binary()},
    {:order_by, order_by_t()}
  ]

  @spec describe_log_streams(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  @spec describe_log_streams(log_group_name :: binary(), opts :: describe_log_streams_opt()) :: ExAws.Operation.JSON.t()
  def describe_log_streams(log_group_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeLogStreams",
      "Version" => @version,
      "logGroupName" => log_group_name
    })

    request(:describe_log_streams, query_params)
  end

  @doc "Describe metric filters"
  @type describe_metric_filters_opt :: [
    {:filter_name_prefix, binary()},
    {:limit, pos_integer()},
    {:log_group_name, binary()},
    {:metric_name, binary()},
    {:metric_namespace, binary()},
    {:next_token, binary()}
  ]

  @spec describe_metric_filters() :: ExAws.Operation.JSON.t()
  @spec describe_metric_filters(opts :: describe_metric_filters_opt()) :: ExAws.Operation.JSON.t()
  def describe_metric_filters(opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeMetricFilters",
      "Version" => @version
    })

    request(:describe_metric_filters, query_params)
  end

  @doc "Describe resource policies"
  @type describe_resource_policies_opt :: [
    {:limit, pos_integer()},
    {:next_token, binary()}
  ]

  @spec describe_resource_policies() :: ExAws.Operation.JSON.t()
  @spec describe_resource_policies(opts :: describe_resource_policies_opt()) :: ExAws.Operation.JSON.t()
  def describe_resource_policies(opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeResourcePolicies",
      "Version" => @version
    })

    request(:describe_resource_policies, query_params)
  end

  @doc "Describe subscription filters"
  @type describe_subscription_filters_opt :: [
    {:filter_name_prefix, binary()},
    {:limit, pos_integer()},
    {:next_token, binary()}
  ]

  @spec describe_subscription_filters(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  @spec describe_subscription_filters(
    log_group_name :: binary(),
    opts :: describe_subscription_filters_opt()) :: ExAws.Operation.JSON.t()
  def describe_subscription_filters(log_group_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "DescribeSubcribeFilters",
      "Version" => @version,
      "logGroupName" => log_group_name
    })

    request(:describe_subscription_filters, query_params)
  end

  @doc "Disassociate KMS key"
  @spec disassociate_kms_key(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def disassociate_kms_key(log_group_name) do
    query_params = %{
      "Action" => "DisassociateKmsKey",
      "Version" => @version,
      "logGroupName" => log_group_name
    }

    request(:disassociate_kms_key, query_params)
  end

  @doc "Filter log events"
  @type filter_log_events_opt :: [
    {:end_time, pos_integer()},
    {:filter_pattern, binary()},
    {:interleaved, binary()},
    {:limit, pos_integer()},
    {:log_stream_names, [binary()]},
    {:next_token, binary()},
    {:start_time, pos_integer()}
  ]

  @spec filter_log_events(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  @spec filter_log_events(log_group_name :: binary(), opts :: filter_log_events_opt()) :: ExAws.Operation.JSON.t()
  def filter_log_events(log_group_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "FilterLogEvents",
      "Version" => @version,
      "logGroupName" => log_group_name
    })

    request(:filter_log_events, query_params)
  end

  @doc "Get log events"
  @type get_log_events_opt :: [
    {:end_time, pos_integer()},
    {:limit, pos_integer()},
    {:next_token, binary()},
    {:start_from_head, binary()},
    {:start_time, pos_integer()}
  ]

  @spec get_log_events(
    log_group_name :: binary(),
    log_stream_name :: binary(),
    opts :: get_log_events_opt()) :: ExAws.Operation.JSON.t()
  def get_log_events(log_group_name, log_stream_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "GetLogEvents",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "logStreamName" => log_stream_name
    })

    request(:get_log_events, query_params)
  end

  @doc "List tags log group"
  @spec list_tags_log_group(log_group_name :: binary()) :: ExAws.Operation.JSON.t()
  def list_tags_log_group(log_group_name) do
    query_params = %{
      "Action" => "ListTagsLogGroup",
      "Version" => @version,
      "logGroupName" => log_group_name
    }

    request(:list_tags_log_group, query_params)
  end

  @doc "Put destination"
  @spec put_destination(
    destination_name :: binary(),
    role_arn :: binary(),
    target_arn :: binary()) :: ExAws.Operation.JSON.t()
  def put_destination(destination_name, role_arn, target_arn) do
    query_params = %{
      "Action" => "PutDestination",
      "Version" => @version,
      "destinationName" => destination_name,
      "roleArn" => role_arn,
      "targetArn" => target_arn
    }

    request(:put_destination, query_params)
  end

  @doc "Put destination policy"
  @spec put_destination_policy(access_policy :: binary(), destination_name :: binary()) :: ExAws.Operation.JSON.t()
  def put_destination_policy(access_policy, destination_name) do
    query_params = %{
      "Action" => "PutDestinationPolicy",
      "Version" => @version,
      "accessPolicy" => access_policy,
      "destinationName" => destination_name
    }

    request(:put_destination_policy, query_params)
  end

  @doc "Put log events"
  @type put_log_events_opt :: [
    {:sequenceToken, binary()}
  ]

  @spec put_log_events(
    log_events :: [map()],
    log_group_name :: binary(),
    log_stream_name :: binary()) :: ExAws.Operation.JSON.t()
  @spec put_log_events(
    log_events :: [map()],
    log_group_name :: binary(),
    log_stream_name :: binary(),
    opts :: put_log_events_opt()) :: ExAws.Operation.JSON.t()
  def put_log_events(log_events, log_group_name, log_stream_name, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "PutLogEvents",
      "Version" => @version,
      "logEvents" => log_events,
      "logGroupName" => log_group_name,
      "logStreamName" => log_stream_name
    })

    request(:put_log_events, query_params)
  end

  @doc "Put metric filter"
  @type metric_transformation_t :: [
    {:default_value, pos_integer()},
    {:metric_name, binary()},
    {:metric_namespace, binary()},
    {:metric_value, binary()}
  ]

  @spec put_metric_filter(
    filter_name :: binary(),
    filter_pattern :: binary(),
    log_group_name :: binary(),
    metric_transformations :: [metric_transformation_t()]) :: ExAws.Operation.JSON.t()

  def put_metric_filter(log_group_name, filter_name, filter_pattern, metric_transformations) do
    query_params = %{
      "Action" => "PutMetricFilter",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "filterName" => filter_name,
      "filterPattern" => filter_pattern,
      "metricTransformations" => lower_camel_case(metric_transformations)
    }

    request(:put_metric_filter, query_params)
  end

  @doc "Put resource policy"
  @type put_resource_policy_opt :: [
    {:policy_document, binary()},
    {:policy_name, binary()}
  ]

  @spec put_resource_policy() :: ExAws.Operation.JSON.t()
  @spec put_resource_policy(opts :: put_resource_policy_opt()) :: ExAws.Operation.JSON.t()
  def put_resource_policy(opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "PutResourcePolicy",
      "Version" => @version
    })

    request(:put_resource_policy, query_params)
  end

  @doc "Put retention policy"
  @spec put_retention_policy(log_group_name :: binary(), retention_in_days :: pos_integer()) :: ExAws.Operation.JSON.t()
  def put_retention_policy(log_group_name, retention_in_days) do
    query_params = %{
      "Action" => "PutRetentionPolicy",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "retentionInDays" => retention_in_days
    }

    request(:put_retention_policy, query_params)
  end

  @doc "Put subscription filter"
  @type put_subscription_filter_opt :: [
    {:distribution, binary()},
    {:role_arn, binary()}
  ]

  @spec put_subscription_filter(
    log_group_name :: binary(),
    destination_arn :: binary(),
    filter_name :: binary(),
    filter_pattern :: binary()) :: ExAws.Operation.JSON.t()
  @spec put_subscription_filter(
    log_group_name :: binary(),
    destination_arn :: binary(),
    filter_name :: binary(),
    filter_pattern :: binary(),
    opts :: put_subscription_filter_opt()) :: ExAws.Operation.JSON.t()
  def put_subscription_filter(log_group_name, destination_arn, filter_name, filter_pattern, opts \\ []) do
    query_params = opts
    |> normalize_opts()
    |> Map.merge(%{
      "Action" => "PutSubscriptionFilter",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "destinationArn" => destination_arn,
      "filterName" => filter_name,
      "filterPattern" => filter_pattern
    })

    request(:put_subscription_filter, query_params)
  end

  @doc "Tag log group"
  @spec tag_log_group(log_group_name :: binary(), tags :: [{binary(), binary()}]) :: ExAws.Operation.JSON.t()
  def tag_log_group(log_group_name, tags) do
    query_params = %{
      "Action" => "TagLogGroup",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "tags" => tags
    }

    request(:tag_log_group, query_params)
  end

  @doc "Test metric filter"
  @spec test_metric_filter(filter_pattern :: binary(), log_event_messages :: [binary()]) :: ExAws.Operation.JSON.t()
  def test_metric_filter(filter_pattern, log_event_messages) do
    query_params = %{
      "Action" => "TestMetricFilter",
      "Version" => @version,
      "filterPattern" => filter_pattern,
      "logEventMessages" => log_event_messages
    }

    request(:test_metric_filter, query_params)
  end

  @doc "Untag log group"
  @spec untag_log_group(log_group_name :: binary(), tags :: [binary()]) :: ExAws.Operation.JSON.t()
  def untag_log_group(log_group_name, tags) do
    query_params = %{
      "Action" => "UntagLogGroup",
      "Version" => @version,
      "logGroupName" => log_group_name,
      "tags" => tags
    }

    request(:untag_log_group, query_params)
  end

  defp request(action, params, opts \\ %{}) do
    operation =
      action
      |> Atom.to_string()
      |> Macro.camelize()

    ExAws.Operation.JSON.new(:logs, %{
          data: params,
          headers: [
            {"x-amz-target", "#{@namespace}.#{operation}"},
            {"content-type", "application/x-amz-json-1.1"}
          ]
    } |> Map.merge(opts))
  end

  defp normalize_opts(opts) do
    opts
    |> Enum.into(%{})
    |> camelize_keys()
    |> lower_camel_case()
  end

  defp lower_camel_case(opts) do
    opts
    |> Enum.reduce(%{},
      fn({k, v}, acc) ->
        Map.put(acc, to_lower_camel_case(k), v)
      end)
  end

  defp to_lower_camel_case(string) do
    {first, rest} = String.split_at(string, 1)

    String.downcase(first) <> rest
  end
end
