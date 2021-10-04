<?php

namespace Menshen;

interface User {
    public function getUid();
    public function getDbId();
    public function getDisplayName();
    public function toJson();
  }