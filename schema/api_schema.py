from pydantic import BaseModel, Field
from typing import List, Optional
from fastapi import UploadFile


class RequirementRequest(BaseModel):
    user_id: Optional[str] = Field(None, description="ユーザーID")
    token: Optional[str] = Field(None, description="認証トークン（ヘッダー利用推奨）")
    client_name: str = Field(..., description="クライアント名")
    text: Optional[str] = Field(None, description="テキスト")


class RequirementResponse(BaseModel):
    status: str = Field(..., description="処理ステータス")
    requirement_text: str = Field(..., description="生成された要求概要のテキスト")


class CaseSummaryRequest(BaseModel):
    user_id: str = Field(..., description="ユーザーID")
    user_name: str = Field(..., description="ユーザー名")
    token: str = Field(..., description="認証トークン（ヘッダー利用推奨）")
    requirement_text: str = Field(..., description="案件の詳細情報（テキスト形式）")
    client_name: str = Field(..., description="クライアント名")


class CaseSummaryResponse(BaseModel):
    status: str = Field(..., description="処理ステータス")
    case_id: str = Field(..., description="生成された案件概要のID")


class ProposalRequest(BaseModel):
    case_num: int = Field(..., description="案件番号")
    candidate_profiles: str = Field(..., description="候補者の情報（テキスト形式）")
    proposal_link: Optional[str] = Field(None, description="proposalリンク")
    skill_sheet: Optional[UploadFile] = Field(None, description="スキルシートファイル")


class ProposalResponse(BaseModel):
    status: str = Field(..., description="処理ステータス")
    proposal_id: str = Field(..., description="生成された提案書のID")
