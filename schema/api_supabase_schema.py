from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID
from datetime import date as DateType

from pydantic import BaseModel, Field, field_validator


def _parse_optional_date(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, DateType):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        text = text.replace("/", "-")
        try:
            parts = text.split("-")
            if len(parts) == 3:
                year, month, day = (int(part) for part in parts)
                return DateType(year, month, day)
            return DateType.fromisoformat(text)
        except Exception:
            return value
    return value


class ClientRecord(BaseModel):
    """Supabase Clients テーブルの取得レコード."""

    id: UUID = Field(..., description="クライアントID")
    created_at: datetime = Field(..., description="作成日時")
    client_name: str = Field(..., description="クライアント名")


class ClientsResponse(BaseModel):
    """Clients テーブルを全件返すレスポンス."""

    clients: List[ClientRecord] = Field(..., description="クライアント一覧")


class CaseManagementRecord(BaseModel):
    """Supabase CaseManagement テーブルの取得レコード."""

    id: UUID = Field(..., description="案件ID")
    created_at: datetime = Field(..., description="作成日時")
    client_id: UUID = Field(..., description="クライアントID")
    number: int = Field(..., description="案件番号")
    case_name: str = Field(..., description="案件名")
    open_opportunity: bool = Field(..., description="募集中フラグ")
    priority: str = Field(..., description="優先度")
    selection_status: str = Field(..., description="選考状況")
    updated_date: datetime = Field(..., description="更新日")
    client_budget: str = Field(..., description="クライアント予算")
    max_monthly_price: str = Field(..., description="月額上限")
    utilization_rate: int = Field(..., description="稼働率")
    remote_availability: str = Field(..., description="リモート可否")
    case_summary: Optional[str] = Field(None, description="案件概要")
    user_id: UUID = Field(..., description="担当ユーザーID")
    user_name: str = Field(..., description="担当ユーザー名")
    speee_note: Optional[str] = Field(None, description="Speee用メモ")
    start_time: Optional[DateType] = Field(None, description="対応開始時間")
    age_limit: Optional[str] = Field(None, description="年齢制限")
    working_place: Optional[str] = Field(None, description="勤務地")
    foreigners_allowed: Optional[bool] = Field(None, description="外国籍可否")
    case_end_date: Optional[DateType] = Field(None, description="募集終了日")

    @field_validator("start_time", mode="before")
    @classmethod
    def _normalize_start_time(cls, value):
        return _parse_optional_date(value)


class CaseManagementResponse(BaseModel):
    """CaseManagement テーブルを全件返すレスポンス."""

    cases: List[CaseManagementRecord] = Field(..., description="案件一覧")


class BpRecord(BaseModel):
    """Supabase Bp テーブルの取得レコード."""

    id: UUID = Field(..., description="BP ID")
    created_at: datetime = Field(..., description="作成日時")
    bp_name: str = Field(..., description="BP 名")
    slack_channel_id: Optional[str] = Field(None, description="Slack チャンネルID")


class BpResponse(BaseModel):
    """Bp テーブルを全件返すレスポンス."""

    bps: List[BpRecord] = Field(..., description="BP 一覧")


class ClientCreateRequest(BaseModel):
    client_name: str = Field(..., description="クライアント名")


class ClientCreateResponse(BaseModel):
    client: ClientRecord = Field(..., description="作成されたクライアント")


class CaseManagementCreateRequest(BaseModel):
    client_id: UUID = Field(..., description="クライアントID")
    number: int = Field(..., description="案件番号")
    case_name: str = Field(..., description="案件名")
    open_opportunity: bool = Field(..., description="募集中フラグ")
    priority: str = Field(..., description="優先度")
    selection_status: str = Field(..., description="選考状況")
    updated_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="更新日",
    )
    client_budget: str = Field(..., description="クライアント予算")
    max_monthly_price: str = Field(..., description="月額上限")
    utilization_rate: int = Field(..., description="稼働率")
    remote_availability: str = Field(..., description="リモート可否")
    case_summary: Optional[str] = Field(None, description="案件概要")
    user_id: UUID = Field(..., description="担当ユーザーID")
    user_name: str = Field(..., description="担当ユーザー名")
    speee_note: Optional[str] = Field(None, description="Speee用メモ")
    start_time: Optional[DateType] = Field(None, description="対応開始時間")
    age_limit: Optional[str] = Field(None, description="年齢制限")
    working_place: Optional[str] = Field(None, description="勤務地")
    foreigners_allowed: Optional[bool] = Field(None, description="外国籍可否")
    case_end_date: Optional[DateType] = Field(None, description="募集終了日")

    @field_validator("start_time", mode="before")
    @classmethod
    def _normalize_start_time(cls, value):
        return _parse_optional_date(value)


class CaseManagementCreateResponse(BaseModel):
    case: CaseManagementRecord = Field(..., description="作成された案件")


class CaseManagementUpdateRequest(BaseModel):
    id: UUID = Field(..., description="案件ID")
    client_id: Optional[UUID] = Field(None, description="クライアントID")
    number: Optional[int] = Field(None, description="案件番号")
    case_name: Optional[str] = Field(None, description="案件名")
    open_opportunity: Optional[bool] = Field(None, description="募集中フラグ")
    priority: Optional[str] = Field(None, description="優先度")
    selection_status: Optional[str] = Field(None, description="選考状況")
    updated_date: Optional[datetime] = Field(None, description="更新日")
    client_budget: Optional[str] = Field(None, description="クライアント予算")
    max_monthly_price: Optional[str] = Field(None, description="月額上限")
    utilization_rate: Optional[int] = Field(None, description="稼働率")
    remote_availability: Optional[str] = Field(None, description="リモート可否")
    case_summary: Optional[str] = Field(None, description="案件概要")
    user_id: Optional[UUID] = Field(None, description="担当ユーザーID")
    user_name: Optional[str] = Field(None, description="担当ユーザー名")
    speee_note: Optional[str] = Field(None, description="Speee用メモ")
    start_time: Optional[DateType] = Field(None, description="対応開始時間")
    age_limit: Optional[str] = Field(None, description="年齢制限")
    working_place: Optional[str] = Field(None, description="勤務地")
    foreigners_allowed: Optional[bool] = Field(None, description="外国籍可否")
    case_end_date: Optional[DateType] = Field(None, description="募集終了日")

    @field_validator("start_time", mode="before")
    @classmethod
    def _normalize_start_time(cls, value):
        return _parse_optional_date(value)


class CaseManagementUpdateResponse(BaseModel):
    case: CaseManagementRecord = Field(..., description="更新後の案件")


class BpCreateRequest(BaseModel):
    bp_name: str = Field(..., description="BP 名")


class BpCreateResponse(BaseModel):
    bp: BpRecord = Field(..., description="作成された BP")


class ProposalRecord(BaseModel):
    """Supabase Proposal テーブルの取得レコード."""

    # 自動出力可
    id: UUID = Field(..., description="提案ID")
    follow_flag: bool = Field(..., description="フォローフラグ（NOアクションから3営業日以上経過）")
    proposal_link: Optional[str] = Field(None, description="proposalリンク")
    proposal_code: Optional[str] = Field(None, description="提案コード")

    # BPからの情報から出力可能
    case_id: Optional[UUID] = Field(None, description="案件ID")
    bp_id: Optional[UUID] = Field(None, description="BP ID")
    candidate_initials: Optional[str] = Field(None, description="候補者名（イニシャル）")
    age: Optional[int] = Field(None, description="年齢")
    candidate_full_name: Optional[str] = Field(None, description="フルネーム")
    bp_link: Optional[str] = Field(None, description="BPリンク")
    cost: Optional[float] = Field(None, description="原価")
    gross_profit: Optional[float] = Field(None, description="粗利")
    utilization: Optional[float] = Field(None, description="稼働率（%）")
    bp_proposal_text: Optional[str] = Field(None, description="BPからの提案内容")

    # AIから出力
    score: Optional[float] = Field(None, description="AIスコア")
    evaluation: Optional[str] = Field(None, description="AI評価コメント")
    proposal: Optional[str] = Field(None, description="提案内容")
    proposal_status: Optional[bool] = Field(None, description="提案するかどうか")
    proposal_code: Optional[str] = Field(None, description="提案コード")

    # 営業担当が入力
    speee_decision: Optional[str] = Field(None, description="Speee 提案/見送り（proposal/decline/undecided）")
    handler: Optional[str] = Field(None, description="対応者（ログイン情報で自動化可）")
    proposal_bp_handler: Optional[str] = Field(None, description="BP側担当者")
    document_examination: Optional[str] = Field(None, description="書類選考結果")
    first_interview: Optional[str] = Field(None, description="1次面談結果")
    final_interview: Optional[str] = Field(None, description="最終面談結果")
    offer: Optional[str] = Field(None, description="オファー結果")
    operation_decision: Optional[str] = Field(None, description="稼働決定結果")
    postpone_decision: Optional[str] = Field(None, description="見送り")
    decline_decision: Optional[str] = Field(None, description="辞退")
    latest_status: Optional[str] = Field(None, description="最新ステータス")


    # システム管理
    created_at: datetime = Field(..., description="作成日時")
    updated_at: datetime = Field(..., description="更新日時")


class ProposalResponse(BaseModel):
    """Proposal テーブルを全件返すレスポンス."""

    proposals: List[ProposalRecord] = Field(..., description="提案一覧")


class ProposalCreateRequest(BaseModel):
    """Proposal 作成リクエスト."""

    case_id: UUID = Field(..., description="案件ID")
    bp_id: Optional[UUID] = Field(None, description="BP ID")
    proposal_code: Optional[str] = Field(None, description="提案コード")
    candidate_initials: Optional[str] = Field(None, description="候補者名（イニシャル）")
    age: Optional[int] = Field(None, description="年齢")
    candidate_full_name: Optional[str] = Field(None, description="フルネーム")
    bp_link: Optional[str] = Field(None, description="BPリンク")
    cost: Optional[float] = Field(None, description="原価")
    gross_profit: Optional[float] = Field(None, description="粗利")
    utilization: Optional[float] = Field(None, description="稼働率（%）")
    score: Optional[float] = Field(None, description="AIスコア")
    evaluation: Optional[str] = Field(None, description="AI評価コメント")
    proposal_status: Optional[bool] = Field(None, description="提案するかどうか")
    speee_decision: Optional[str] = Field(None, description="Speee 提案/見送り（proposal/decline/undecided）")
    handler: Optional[str] = Field(None, description="対応者（ログイン情報で自動化可）")
    proposal_bp_handler: Optional[str] = Field(None, description="BP側担当者")
    document_examination: Optional[str] = Field(None, description="書類選考結果")
    first_interview: Optional[str] = Field(None, description="1次面談結果")
    final_interview: Optional[str] = Field(None, description="最終面談結果")
    offer: Optional[str] = Field(None, description="オファー結果")
    operation_decision: Optional[str] = Field(None, description="稼働決定結果")
    postpone_decision: Optional[str] = Field(None, description="見送り理由")
    decline_decision: Optional[str] = Field(None, description="辞退理由")
    latest_status: Optional[str] = Field(None, description="最新ステータス")
    proposal: Optional[str] = Field(None, description="提案内容")
    bp_proposal_text: Optional[str] = Field(None, description="BPからの提案内容")


class ProposalCreateResponse(BaseModel):
    """Proposal 作成レスポンス."""

    proposal: ProposalRecord = Field(..., description="作成された提案")


class ProposalUpdateRequest(BaseModel):
    """Proposal 更新リクエスト."""

    id: UUID = Field(..., description="提案ID")
    follow_flag: Optional[bool] = Field(None, description="フォローフラグ")
    proposal_link: Optional[str] = Field(None, description="proposalリンク")
    proposal_code: Optional[str] = Field(None, description="提案コード")
    case_id: Optional[UUID] = Field(None, description="案件ID")
    bp_id: Optional[UUID] = Field(None, description="BP ID")
    candidate_initials: Optional[str] = Field(None, description="候補者名（イニシャル）")
    age: Optional[int] = Field(None, description="年齢")
    candidate_full_name: Optional[str] = Field(None, description="フルネーム")
    bp_link: Optional[str] = Field(None, description="BPリンク")
    cost: Optional[float] = Field(None, description="原価")
    gross_profit: Optional[float] = Field(None, description="粗利")
    utilization: Optional[float] = Field(None, description="稼働率（%）")
    score: Optional[float] = Field(None, description="AIスコア")
    evaluation: Optional[str] = Field(None, description="AI評価コメント")
    proposal_status: Optional[bool] = Field(None, description="提案するかどうか")
    speee_decision: Optional[str] = Field(None, description="Speee 提案/見送り（proposal/decline/undecided）")
    handler: Optional[str] = Field(None, description="対応者")
    proposal_bp_handler: Optional[str] = Field(None, description="BP側担当者")
    document_examination: Optional[str] = Field(None, description="書類選考結果")
    first_interview: Optional[str] = Field(None, description="1次面談結果")
    final_interview: Optional[str] = Field(None, description="最終面談結果")
    offer: Optional[str] = Field(None, description="オファー結果")
    operation_decision: Optional[str] = Field(None, description="稼働決定結果")
    postpone_decision: Optional[str] = Field(None, description="見送り理由")
    decline_decision: Optional[str] = Field(None, description="辞退理由")
    latest_status: Optional[str] = Field(None, description="最新ステータス")
    proposal: Optional[str] = Field(None, description="提案内容")
    bp_proposal_text: Optional[str] = Field(None, description="BPからの提案内容")


class ProposalUpdateResponse(BaseModel):
    """Proposal 更新レスポンス."""

    proposal: ProposalRecord = Field(..., description="更新後の提案")


class ProposalStatusUpdateRequest(BaseModel):
    """提案ごとの各ステータス更新リクエスト."""

    id: UUID = Field(..., description="提案ID")
    status: str = Field(..., description="更新対象ステータス")
    date: Optional[DateType] = Field(None, description="ステータス日付")
    comment: Optional[str] = Field(None, description="ステータスコメント")


class SpeeeDecisionUpdateRequest(BaseModel):
    """Speee決裁ステータス更新リクエスト."""

    id: UUID = Field(..., description="提案ID")
    stats: str = Field(..., description="Speee決裁ステータス (propose/postpone)")
    date: Optional[DateType] = Field(None, description="ステータス日付")
    comment: Optional[str] = Field(None, description="備考コメント")
