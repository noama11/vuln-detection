bool AsyncPixelTransfersCompletedQuery::End(
    base::subtle::Atomic32 submit_count) {
  AsyncMemoryParams mem_params;
  // Get the real shared memory since it might need to be duped to prevent
  // use-after-free of the memory.
  Buffer buffer = manager()->decoder()->GetSharedMemoryBuffer(shm_id());
  if (!buffer.shared_memory)
    return false;
  mem_params.shared_memory = buffer.shared_memory;
  mem_params.shm_size = buffer.size;
  mem_params.shm_data_offset = shm_offset();
  mem_params.shm_data_size = sizeof(QuerySync);

  observer_ = new AsyncPixelTransferCompletionObserverImpl(submit_count);

  // Ask AsyncPixelTransferDelegate to run completion callback after all
  // previous async transfers are done. No guarantee that callback is run
  // on the current thread.
  manager()->decoder()->GetAsyncPixelTransferManager()
      ->AsyncNotifyCompletion(mem_params, observer_);

  return AddToPendingTransferQueue(submit_count);
}